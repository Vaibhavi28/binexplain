from apscheduler.schedulers.background import BackgroundScheduler
from knowledge_base.scraper import WriteupScraper
from knowledge_base.rag_engine import CTFKnowledgeBase


def refresh_knowledge_base():
    print("[Scheduler] Starting knowledge base refresh...")
    scraper = WriteupScraper()
    scraper.run()
    kb = CTFKnowledgeBase()
    kb.update_from_scraper()
    print("[Scheduler] Knowledge base refresh complete")


def start_scheduler():
    scheduler = BackgroundScheduler()
    scheduler.add_job(refresh_knowledge_base, 'interval', hours=24)
    scheduler.start()
    print("[BinExplain] Auto-refresh scheduler started (every 24 hours)")
    return scheduler
