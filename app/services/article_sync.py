from __future__ import annotations

from datetime import datetime, timezone, timedelta
import os
import re
from typing import Any, Callable

import requests
from sqlalchemy import select, func, delete
from sqlalchemy.orm import Session

from app import models

ARTICLE_FEED_NAME = "general_health_articles"
ARTICLE_STALE_AFTER_HOURS = 4  # switch to 4 once done testing
RETRIEVAL_ONLY = False  # set False before restoring normal database sync behavior
MAX_ARTICLES = 500

TARGET_ARTICLES_PER_SYNC = 10
MAX_ARTICLES_PER_TOPIC = 2
SAME_TOPIC_OVERLAP_THRESHOLD = 0.30

NEWSDATA_API_KEY = os.getenv("NEWSDATA_API_KEY")
NEWSDATA_BASE_URL = "https://newsdata.io/api/1/latest"

# NewsData keyword/search parameters have a 100-character limit.
NEWSDATA_QUERY_MAX_LENGTH = 100

# NewsData is already queried with language=en, but keep a local safeguard
# against rare provider-side language classification leaks.
ENGLISH_LANGUAGE_VALUES = {
    "english",
    "en",
    "en-us",
    "en_us",
    "en-gb",
    "en_gb",
}

# Local ranking preference only. Non-U.S. stories are NOT rejected.
# U.S.-tagged NewsData results are simply considered first.
US_COUNTRY_VALUES = {
    "us",
    "usa",
    "united states",
    "united states of america",
}

# Priority search:
# - Search specifically for actual recall headlines first.
# - Restrict results to NewsData's health + food categories.
# - If fewer than 10 diverse recalls survive filtering, general health fills
#   the remaining slots.
RECALL_TITLE_QUERY = "recall OR recalled OR recalls"

# General fallback:
# - Search only title/URL/meta description/meta keywords.
# - Do not include a generic word such as "warning", which can pull weather,
#   politics, travel, and other unrelated stories.
GENERAL_HEALTH_META_QUERY = (
    "disease OR outbreak OR vaccine OR medication OR drug OR FDA "
    "OR treatment OR infection OR symptoms"
)

# A priority result must have BOTH:
#   1. a recall/outbreak/contamination signal, and
#   2. health/food/medical context in its title or description.
RECALL_SIGNAL_TERMS = {
    "recall",
    "recalled",
    "recalls",
}

# A real recall should also have product/regulatory/safety context.
# This prevents headlines such as "Celebrity recalls painful experience..."
# from qualifying just because the verb "recalls" appears beside a health term.
RECALL_PRODUCT_CONTEXT_TERMS = {
    "food",
    "foods",
    "drug",
    "drugs",
    "medication",
    "medications",
    "supplement",
    "supplements",
    "fda",
    "usda",
    "salmonella",
    "listeria",
    "coli",
    "cyclospora",
    "allergen",
    "allergens",
    "undeclared",
    "contamination",
    "contaminated",
    "bacteria",
    "bacterial",
    "pathogen",
    "pathogens",
    "poisoning",
    "mold",
    "mould",
}

HEALTH_CONTEXT_TERMS = {
    "health",
    "medical",
    "medicine",
    "drug",
    "drugs",
    "medication",
    "medications",
    "pharmaceutical",
    "pharmaceuticals",
    "fda",
    "usda",
    "cdc",
    "food",
    "foods",
    "salmonella",
    "listeria",
    "coli",
    "cyclospora",
    "bacteria",
    "bacterial",
    "virus",
    "viral",
    "infection",
    "infections",
    "illness",
    "illnesses",
    "disease",
    "diseases",
    "vaccine",
    "vaccines",
    "treatment",
    "treatments",
    "clinical",
    "cancer",
    "heart",
    "nutrition",
    "diet",
    "ebola",
    "measles",
    "mpox",
    "norovirus",
    "hepatitis",
    "botulism",
    "parasite",
    "parasitic",
    "diarrhea",
    "diarrhoea",
    "allergy",
    "allergies",
    "allergen",
    "allergens",
    "undeclared",
    "pathogen",
    "pathogens",
    "poisoning",
    "mold",
    "mould",
}

# Broader local gate for the general-health fallback. This prevents a provider
# category/query false positive from being stored as health news.
GENERAL_HEALTH_TERMS = {
    "disease",
    "diseases",
    "outbreak",
    "outbreaks",
    "vaccine",
    "vaccines",
    "medication",
    "medications",
    "drug",
    "drugs",
    "fda",
    "treatment",
    "treatments",
    "infection",
    "infections",
    "symptom",
    "symptoms",
    "diagnosis",
    "diagnosed",
    "clinical",
    "cancer",
    "heart",
    "cardiac",
    "stroke",
    "diabetes",
    "obesity",
    "mental",
    "brain",
    "virus",
    "viral",
    "bacteria",
    "bacterial",
    "salmonella",
    "listeria",
    "cyclospora",
    "ebola",
    "measles",
    "mpox",
    "norovirus",
    "hepatitis",
    "botulism",
    "parasite",
    "parasitic",
    "allergen",
    "allergens",
    "therapy",
    "therapies",
    "nutrition",
    "exercise",
}


TITLE_TOPIC_STOPWORDS = {
    "a", "an", "and", "are", "as", "at", "be", "because", "by", "for",
    "from", "has", "have", "in", "is", "it", "its", "new", "news", "of",
    "on", "over", "recall", "recalled", "recalls", "safety", "alert",
    "update", "updates", "warning", "warnings", "the", "to", "with",
    "outbreak", "outbreaks", "report", "reports", "latest",
}


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _validate_newsdata_search_params(params: dict[str, Any]) -> None:
    for key in ("q", "qInTitle", "qInMeta"):
        value = params.get(key)

        if value is None:
            continue

        length = len(str(value))

        if length > NEWSDATA_QUERY_MAX_LENGTH:
            raise ValueError(
                f"NewsData.io {key} exceeds "
                f"{NEWSDATA_QUERY_MAX_LENGTH} characters: {length}"
            )


def _is_english_newsdata_item(item: dict[str, Any]) -> bool:
    raw_language = item.get("language")

    if isinstance(raw_language, list):
        values = {
            str(value).strip().lower()
            for value in raw_language
            if value is not None
        }
        return bool(values & ENGLISH_LANGUAGE_VALUES)

    language = str(raw_language or "").strip().lower()
    return language in ENGLISH_LANGUAGE_VALUES


def _filter_english_payloads(
    items: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    english_items: list[dict[str, Any]] = []

    for item in items:
        if _is_english_newsdata_item(item):
            english_items.append(item)
            continue

        title = str(item.get("title") or "Untitled article")
        language = item.get("language")

        print(
            "Article sync rejected non-English result: "
            f"language={language!r}, title={title}"
        )

    return english_items


def _is_us_newsdata_item(item: dict[str, Any]) -> bool:
    """
    Return True when NewsData tags a result as U.S.-based.

    This is only a ranking signal. Missing or non-U.S. country metadata
    remains fully eligible for the feed.
    """
    raw_country = item.get("country")

    if isinstance(raw_country, list):
        values = {
            str(value).strip().lower()
            for value in raw_country
            if value is not None
        }
        return bool(values & US_COUNTRY_VALUES)

    country = str(raw_country or "").strip().lower()
    return country in US_COUNTRY_VALUES


def _prioritize_us_payloads(
    items: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Stable local ranking: U.S.-tagged stories first, then all others.

    Python's sort is stable, so NewsData's existing ordering is preserved
    within each group.
    """
    return sorted(
        items,
        key=lambda item: 0 if _is_us_newsdata_item(item) else 1,
    )


def _fetch_newsdata(params: dict[str, Any]) -> list[dict[str, Any]]:
    if not NEWSDATA_API_KEY:
        raise RuntimeError("NEWSDATA_API_KEY is not configured")

    _validate_newsdata_search_params(params)

    request_params = {
        "apikey": NEWSDATA_API_KEY,
        "language": "en",
        "size": TARGET_ARTICLES_PER_SYNC,
        "removeduplicate": 1,
        **params,
    }

    response = requests.get(
        NEWSDATA_BASE_URL,
        params=request_params,
        timeout=20,
    )

    if not response.ok:
        try:
            error_body = response.json()
        except ValueError:
            error_body = response.text

        raise RuntimeError(
            f"NewsData.io request failed with HTTP {response.status_code}: "
            f"{error_body}"
        )

    try:
        data = response.json()
    except ValueError as exc:
        raise RuntimeError(
            "NewsData.io returned a non-JSON response."
        ) from exc

    if data.get("status") != "success":
        raise RuntimeError(f"NewsData.io error: {data}")

    results = data.get("results", [])

    if not isinstance(results, list):
        return []

    return _filter_english_payloads(results)


def fetch_recall_article_payloads() -> list[dict[str, Any]]:
    """
    High-priority recall pass.

    NewsData supports both "health" and "food" categories, so using both lets
    food recalls through without opening the search to unrelated categories.
    qInTitle keeps the recall signal in the headline instead of allowing a
    stray word anywhere in the full article to qualify it.
    """
    return _fetch_newsdata(
        {
            "qInTitle": RECALL_TITLE_QUERY,
            "category": "health,food",
        }
    )


def fetch_general_article_payloads() -> list[dict[str, Any]]:
    """
    General-health fallback.

    qInMeta is narrower than q: NewsData limits it to title, URL, metadata
    keywords and description instead of searching the entire article.
    """
    return _fetch_newsdata(
        {
            "category": "health",
            "qInMeta": GENERAL_HEALTH_META_QUERY,
        }
    )


def articles_exist(db: Session) -> bool:
    count = db.execute(
        select(func.count()).select_from(models.ExternalArticle)
    ).scalar_one()
    return count > 0


def _parse_article_date(value: str | None):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return None


def normalize_article_item(
    item: dict[str, Any],
    topic: str = "health_news",
    related_drug_name: str | None = None,
) -> dict[str, Any]:
    title = item.get("title") or "Article"
    summary = item.get("description")
    url = item.get("link")
    image_url = item.get("image_url")
    published_raw = item.get("pubDate")
    source_name = item.get("source_id") or "Unknown"

    external_id = item.get("article_id") or url or title

    return {
        "source": str(source_name),
        "topic": topic,
        "external_id": str(external_id),
        "title": str(title),
        "summary": summary,
        "url": url or str(title),
        "image_url": image_url,
        "published_at": _parse_article_date(published_raw),
        "related_drug_name": related_drug_name,
        "matched_display_name": related_drug_name,
        "raw_json": item,
    }


def _get_or_create_sync_state(
    db: Session,
    feed_name: str,
) -> models.ExternalFeedSync:
    sync = db.execute(
        select(models.ExternalFeedSync).where(
            models.ExternalFeedSync.feed_name == feed_name
        )
    ).scalars().first()

    if sync:
        return sync

    sync = models.ExternalFeedSync(
        feed_name=feed_name,
        status="never_run",
    )
    db.add(sync)
    db.flush()
    return sync


def _normalize_title(value: str | None) -> str:
    return " ".join((value or "").strip().lower().split())


def _normalize_search_text(value: str | None) -> str:
    text = (value or "").lower()
    return " ".join(re.findall(r"[a-z0-9]+", text))


def _article_relevance_text(item: dict[str, Any]) -> str:
    """
    Deliberately validate against the user-facing headline/description rather
    than the full article body. A stray term deep in an unrelated article
    should not be enough to put it into the GermFx health feed.
    """
    pieces = [
        str(item.get("title") or ""),
        str(item.get("description") or ""),
    ]

    keywords = item.get("keywords")
    if isinstance(keywords, list):
        pieces.extend(str(keyword) for keyword in keywords if keyword)
    elif keywords:
        pieces.append(str(keywords))

    return _normalize_search_text(" ".join(pieces))


def _contains_any_term(text: str, terms: set[str]) -> bool:
    words = set(text.split())
    return any(term in words for term in terms)


def _is_recall_relevant(item: dict[str, Any]) -> bool:
    text = _article_relevance_text(item)

    return (
        _contains_any_term(text, RECALL_SIGNAL_TERMS)
        and _contains_any_term(text, RECALL_PRODUCT_CONTEXT_TERMS)
    )


def _is_general_health_relevant(item: dict[str, Any]) -> bool:
    text = _article_relevance_text(item)
    return _contains_any_term(text, GENERAL_HEALTH_TERMS)


def _filter_relevant_payloads(
    items: list[dict[str, Any]],
    *,
    feed_name: str,
    predicate: Callable[[dict[str, Any]], bool],
) -> list[dict[str, Any]]:
    relevant: list[dict[str, Any]] = []

    for item in items:
        if predicate(item):
            relevant.append(item)
            continue

        title = str(item.get("title") or "Untitled article")
        print(
            f"Article sync rejected [{feed_name}] non-health result: "
            f"{title}"
        )

    return relevant


def _title_topic_tokens(value: str | None) -> set[str]:
    # Publisher names are often appended as " - Source Name" and make two
    # headlines about the same event look less similar than they really are.
    headline = (value or "").split(" - ", 1)[0]

    words = re.findall(r"[a-z0-9]+", _normalize_title(headline))
    normalized_words: set[str] = set()

    for word in words:
        if word == "drc":
            word = "congo"

        if word.isdigit():
            continue

        if len(word) < 3 or word in TITLE_TOPIC_STOPWORDS:
            continue

        normalized_words.add(word)

    return normalized_words


def _titles_are_same_topic(
    first_title: str | None,
    second_title: str | None,
) -> bool:
    first = _title_topic_tokens(first_title)
    second = _title_topic_tokens(second_title)

    if not first or not second:
        return False

    shared_terms = first & second

    # One generic shared word is not enough to call two stories the same
    # topic. Requiring at least two meaningful shared terms keeps unrelated
    # health stories from being grouped together.
    if len(shared_terms) < 2:
        return False

    overlap = len(shared_terms) / min(len(first), len(second))
    return overlap >= SAME_TOPIC_OVERLAP_THRESHOLD


def _article_identity(item: dict[str, Any]) -> str:
    article_id = str(item.get("article_id") or "").strip().lower()
    if article_id:
        return f"id:{article_id}"

    link = str(item.get("link") or "").strip().lower()
    if link:
        return f"url:{link}"

    return f"title:{_normalize_title(str(item.get('title') or ''))}"


def _dedupe_payloads(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen_identities: set[str] = set()
    seen_titles: set[str] = set()
    unique: list[dict[str, Any]] = []

    for item in items:
        identity = _article_identity(item)
        normalized_title = _normalize_title(str(item.get("title") or ""))

        if identity in seen_identities:
            continue

        if normalized_title and normalized_title in seen_titles:
            continue

        seen_identities.add(identity)
        if normalized_title:
            seen_titles.add(normalized_title)

        unique.append(item)

    return unique


def _add_diverse_articles(
    selected: list[dict[str, Any]],
    candidates: list[dict[str, Any]],
    *,
    limit: int,
) -> None:
    for candidate in candidates:
        if len(selected) >= limit:
            return

        candidate_title = str(candidate.get("title") or "")
        candidate_identity = _article_identity(candidate)
        candidate_normalized_title = _normalize_title(candidate_title)

        duplicate = any(
            _article_identity(existing) == candidate_identity
            or (
                candidate_normalized_title
                and _normalize_title(str(existing.get("title") or ""))
                == candidate_normalized_title
            )
            for existing in selected
        )

        if duplicate:
            continue

        same_topic_count = sum(
            1
            for existing in selected
            if _titles_are_same_topic(
                candidate_title,
                str(existing.get("title") or ""),
            )
        )

        if same_topic_count >= MAX_ARTICLES_PER_TOPIC:
            continue

        selected.append(candidate)


def fetch_prioritized_article_payloads() -> tuple[
    list[dict[str, Any]],
    dict[str, int],
]:
    recall_raw = fetch_recall_article_payloads()

    recall_relevant = _filter_relevant_payloads(
        recall_raw,
        feed_name="recall",
        predicate=_is_recall_relevant,
    )
    recall_candidates = _prioritize_us_payloads(
        _dedupe_payloads(recall_relevant)
    )

    selected: list[dict[str, Any]] = []
    _add_diverse_articles(
        selected,
        recall_candidates,
        limit=TARGET_ARTICLES_PER_SYNC,
    )

    recall_selected_count = len(selected)
    general_raw: list[dict[str, Any]] = []
    general_relevant: list[dict[str, Any]] = []
    general_candidates: list[dict[str, Any]] = []

    if len(selected) < TARGET_ARTICLES_PER_SYNC:
        general_raw = fetch_general_article_payloads()

        general_relevant = _filter_relevant_payloads(
            general_raw,
            feed_name="general",
            predicate=_is_general_health_relevant,
        )
        general_candidates = _prioritize_us_payloads(
            _dedupe_payloads(general_relevant)
        )

        _add_diverse_articles(
            selected,
            general_candidates,
            limit=TARGET_ARTICLES_PER_SYNC,
        )

    stats = {
        "recall_returned": len(recall_raw),
        "recall_relevant": len(recall_relevant),
        "recall_us_candidates": sum(
            1 for item in recall_candidates if _is_us_newsdata_item(item)
        ),
        "recall_selected": recall_selected_count,
        "general_returned": len(general_raw),
        "general_relevant": len(general_relevant),
        "general_us_candidates": sum(
            1 for item in general_candidates if _is_us_newsdata_item(item)
        ),
        "selected": len(selected),
        "selected_us": sum(
            1 for item in selected if _is_us_newsdata_item(item)
        ),
    }

    print(f"Article sync stats: {stats}")
    print(f"slected article titles: {[item.get('title') for item in selected]}")
    return selected, stats


def upsert_articles(db: Session, normalized_items: list[dict[str, Any]]) -> int:
    count = 0

    existing_articles = db.execute(
        select(models.ExternalArticle)
    ).scalars().all()

    articles_by_title = {
        _normalize_title(article.title): article
        for article in existing_articles
        if article.title
    }

    for item in normalized_items:
        existing = db.execute(
            select(models.ExternalArticle).where(
                models.ExternalArticle.source == item["source"],
                models.ExternalArticle.external_id == item["external_id"],
            )
        ).scalars().first()

        if not existing:
            existing = articles_by_title.get(_normalize_title(item["title"]))

        if existing:
            existing.topic = item["topic"]
            existing.title = item["title"]
            existing.summary = item["summary"]
            existing.url = item["url"]
            existing.image_url = item["image_url"]
            existing.published_at = item["published_at"]
            existing.related_drug_name = item["related_drug_name"]
            existing.matched_display_name = item["matched_display_name"]
            existing.raw_json = item["raw_json"]
            db.add(existing)
        else:
            article = models.ExternalArticle(**item)
            db.add(article)
            articles_by_title[_normalize_title(item["title"])] = article

        count += 1

    return count


def prune_old_articles(db: Session, keep: int = MAX_ARTICLES) -> int:
    total = db.execute(
        select(func.count()).select_from(models.ExternalArticle)
    ).scalar_one()

    overflow = total - keep
    if overflow <= 0:
        return 0

    oldest_ids = db.execute(
        select(models.ExternalArticle.id)
        .order_by(
            models.ExternalArticle.published_at.asc().nullsfirst(),
            models.ExternalArticle.created_at.asc(),
        )
        .limit(overflow)
    ).scalars().all()

    if not oldest_ids:
        return 0

    # Reactions are not snapshots and should not outlive their source article.
    # Saved items intentionally remain because they store article snapshots.
    db.execute(
        delete(models.ContentReaction).where(
            models.ContentReaction.content_type == "news",
            models.ContentReaction.source_item_id.in_(oldest_ids),
        )
    )

    db.execute(
        delete(models.ExternalArticle).where(
            models.ExternalArticle.id.in_(oldest_ids)
        )
    )

    return len(oldest_ids)


def sync_general_articles(db: Session) -> dict:
    sync = _get_or_create_sync_state(db, ARTICLE_FEED_NAME)

    if not RETRIEVAL_ONLY:
        sync.status = "running"
        sync.notes = None
        db.add(sync)
        db.commit()

    try:
        fetched_items, fetch_stats = fetch_prioritized_article_payloads()

        normalized = [
            normalize_article_item(item, topic="health_news")
            for item in fetched_items
        ]
        
        print(
            "normalized article titles:",
            [item.get("title") for item in normalized],
        )

        if RETRIEVAL_ONLY:
            # Testing mode: do not stage INSERT/UPDATE/DELETE operations at all.
            # Discard any uncommitted sync-state object work and return only
            # retrieval/filtering diagnostics.
            db.rollback()

            return {
                "feed_name": ARTICLE_FEED_NAME,
                "retrieval_only": True,
                **fetch_stats,
            }

        upserted = upsert_articles(db, normalized)
        deleted = prune_old_articles(db, keep=MAX_ARTICLES)

        sync.last_synced_at = _now_utc()
        sync.status = "success"
        sync.notes = (
            f"Recall returned {fetch_stats['recall_returned']}, "
            f"relevant {fetch_stats['recall_relevant']}, "
            f"selected {fetch_stats['recall_selected']}; "
            f"general returned {fetch_stats['general_returned']}, "
            f"relevant {fetch_stats['general_relevant']}; "
            f"final batch {fetch_stats['selected']}; "
            f"upserted {upserted}, pruned {deleted} old records"
        )

    
        db.add(sync)
        db.commit()

        print(
            f"Article sync completed: upserted {upserted}, pruned {deleted} old records")
        return {
            "feed_name": ARTICLE_FEED_NAME,
            "upserted": upserted,
            "pruned": deleted,
            **fetch_stats,
        }

    except Exception as e:
        print(f"Article sync failed: {e}")
        db.rollback()

        sync = _get_or_create_sync_state(db, ARTICLE_FEED_NAME)
        sync.last_synced_at = _now_utc()
        sync.status = "failed"
        sync.notes = str(e)
        db.add(sync)
        db.commit()
        raise


def ensure_articles_fresh(db: Session) -> dict:
    sync = _get_or_create_sync_state(db, ARTICLE_FEED_NAME)
    db.commit()

    is_empty = not articles_exist(db)
    is_stale = (
        not sync.last_synced_at
        or sync.last_synced_at
        < (_now_utc() - timedelta(hours=ARTICLE_STALE_AFTER_HOURS))
    )

    print(
        "Article sync check: "
        f"is_empty={is_empty}, "
        f"is_stale={is_stale}, "
        f"last_synced_at={sync.last_synced_at}"
    )

    if is_empty or is_stale:
        return sync_general_articles(db)

    return {
        "feed_name": ARTICLE_FEED_NAME,
        "skipped": True,
        "reason": "fresh",
        "last_synced_at": sync.last_synced_at,
    }