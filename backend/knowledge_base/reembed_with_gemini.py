"""
One-time migration script: re-embed all existing ChromaDB writeups using Gemini.

Run this ONCE on your laptop (not the server) after patching rag_engine.py.
The server's chroma_db was empty, so this script is for local use only.
After running, copy the chroma_db folder to the server with scp.

Usage:
    cd C:\Users\91797\OneDrive\Desktop\BinExplain
    C:\Users\91797\miniconda3\python.exe backend/knowledge_base/reembed_with_gemini.py
"""
import sys
import os
import time

# Make sure we can import from backend/
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from knowledge_base.rag_engine import CTFKnowledgeBase, _gemini_embed


def reembed_all():
    print("[Re-embed] Loading CTFKnowledgeBase...")
    kb = CTFKnowledgeBase()
    collection = kb.collection

    total = collection.count()
    print(f"[Re-embed] Found {total} documents in ChromaDB")

    if total == 0:
        print("[Re-embed] Collection is empty — nothing to re-embed.")
        print("[Re-embed] Run load_all_walkthroughs() first by instantiating CTFKnowledgeBase.")
        return

    # Fetch all documents in one shot
    all_data = collection.get(include=["documents", "metadatas"])
    ids = all_data["ids"]
    documents = all_data["documents"]
    metadatas = all_data["metadatas"]

    print(f"[Re-embed] Starting Gemini re-embedding of {len(ids)} documents...")
    print(f"[Re-embed] Estimated time: ~{len(ids) * 0.06 / 60:.1f} minutes at 60ms/doc")

    new_embeddings = []
    failed_ids = []

    for i, (doc_id, doc) in enumerate(zip(ids, documents)):
        emb = _gemini_embed(doc, "retrieval_document")
        if emb is None:
            failed_ids.append(doc_id)
            new_embeddings.append([0.0] * 768)  # zero vector fallback
        else:
            new_embeddings.append(emb)

        if (i + 1) % 50 == 0:
            pct = (i + 1) / len(ids) * 100
            print(f"[Re-embed] Progress: {i + 1}/{len(ids)} ({pct:.1f}%) | Failures so far: {len(failed_ids)}")

        time.sleep(0.06)  # 60ms = ~16 docs/sec, safely within Gemini free tier limits

    print(f"[Re-embed] Updating ChromaDB with new Gemini embeddings...")
    # Update in batches of 100 to avoid memory spikes
    batch_size = 100
    for start in range(0, len(ids), batch_size):
        end = min(start + batch_size, len(ids))
        collection.update(
            ids=ids[start:end],
            embeddings=new_embeddings[start:end],
        )
        print(f"[Re-embed] Updated batch {start}–{end}")

    print(f"\n[Re-embed] DONE.")
    print(f"  Successfully re-embedded: {len(ids) - len(failed_ids)}/{len(ids)}")
    if failed_ids:
        print(f"  Failed (got zero vector): {len(failed_ids)}")
        print(f"  Failed IDs: {failed_ids[:10]}{'...' if len(failed_ids) > 10 else ''}")
        print(f"  These documents will return poor similarity scores.")
    else:
        print(f"  All documents successfully re-embedded with Gemini.")
    print(f"\n[Re-embed] Next step: copy chroma_db to your server:")
    print(f"  scp -r backend/knowledge_base/chroma_db YOUR_USER@YOUR_SERVER_IP:/path/to/app/backend/knowledge_base/")


if __name__ == "__main__":
    reembed_all()
