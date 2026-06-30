import os
import glob as _glob
os.environ["TOKENIZERS_PARALLELISM"] = "false"

def build_rag_query(binary_context: dict, user_question: str = "") -> str:
    parts = []
    category = binary_context.get("ctf_category", "")
    if isinstance(category, dict):
        category = category.get("category", "")
    if category:
        parts.append(f"CTF {category} challenge writeup exploit solution")

    # Look for protections dict in either 'protections' or 'checksec'
    protections = binary_context.get("protections") or binary_context.get("checksec") or {}
    if protections:
        active = [k for k, v in protections.items()
                  if str(v).lower() not in ["disabled", "no", "none", "false", "0", "unknown"]]
        if active:
            parts.append(f"bypass {' '.join(active)} binary")

    arch = binary_context.get("architecture", "")
    if arch:
        parts.append(f"{arch} binary exploit")

    # In raw analysis_data, functions might be under 'function_list' or 'functions'
    functions = binary_context.get("functions") or binary_context.get("function_list") or []
    interesting = ["win", "system", "gets", "printf", "scanf", "vuln", "shell", "flag"]
    found = [f for f in functions if any(kw in str(f).lower() for kw in interesting)]
    if found:
        parts.append(f"functions {' '.join(str(f) for f in found[:3])}")

    fmt_found = False
    if binary_context.get("format_string_found"):
        fmt_found = True
    else:
        fmt = binary_context.get("format_string")
        if isinstance(fmt, dict) and fmt.get("detected"):
            fmt_found = True
        elif isinstance(fmt, bool) and fmt:
            fmt_found = True
            
    if fmt_found:
        parts.append("format string printf vulnerability exploit")

    if user_question:
        parts.append(user_question)

    return " ".join(parts)[:500]

class CTFKnowledgeBase:

    def __init__(self):
        import chromadb
        use_persistent = os.getenv("KB_PERSISTENT", "true").lower() == "true"
        
        if use_persistent:
            self.client = chromadb.PersistentClient(path="backend/knowledge_base/chroma_db")
            print("[BinExplain KB] Using persistent ChromaDB")
        else:
            self.client = chromadb.Client()
            print("[BinExplain KB] Using in-memory ChromaDB")
            
        self.collection = self.client.get_or_create_collection("ctf_writeups")
        self.model = None
        self.load_all_walkthroughs()
        count = self.collection.count()
        print(f"[BinExplain KB] Ready with {count} documents")
        
    def load_all_walkthroughs(self):
        # 1. Scan every .txt file in backend/knowledge_base/walkthroughs/
        base_dir = os.path.dirname(os.path.abspath(__file__))
        walkthroughs_dir = os.path.join(base_dir, "walkthroughs")
        if not os.path.exists(walkthroughs_dir):
            print(f"[BinExplain KB] Walkthroughs directory {walkthroughs_dir} does not exist.")
            return

        new_count = 0
        # Recursive glob — finds files in walkthroughs/ AND any subfolders (e.g. ctftime/, github/)
        txt_files = _glob.glob(os.path.join(walkthroughs_dir, "**", "*.txt"), recursive=True)

        # Get all already-indexed IDs in one shot to avoid per-file round trips
        existing_ids = set()
        try:
            all_existing = self.collection.get(include=[])
            existing_ids = set(all_existing.get("ids", []))
        except Exception:
            pass

        # Batch accumulators
        batch_docs, batch_metas, batch_ids = [], [], []

        def flush_batch():
            nonlocal new_count
            if not batch_docs:
                return
            self.collection.add(documents=batch_docs, metadatas=batch_metas, ids=batch_ids)
            new_count += len(batch_docs)
            batch_docs.clear(); batch_metas.clear(); batch_ids.clear()

        for filepath in txt_files:
            filename = os.path.basename(filepath)
            rel_path = os.path.relpath(filepath, walkthroughs_dir)
            doc_id = os.path.splitext(rel_path)[0].replace(os.sep, "/")

            if doc_id in existing_ids:
                continue

            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except Exception as e:
                print(f"[BinExplain KB] Error reading file {filepath}: {e}")
                continue

            parts = content.split("---", 2)
            if len(parts) < 3:
                header_data = {}
                body_text = content
            else:
                header_text = parts[1]
                body_text = parts[2]
                header_data = {}
                for line in header_text.strip().splitlines():
                    if ":" in line:
                        k, v = line.split(":", 1)
                        header_data[k.strip().upper()] = v.strip()

            metadata = {
                "source":          header_data.get("SOURCE", ""),
                "url":             header_data.get("URL", ""),
                "challenge":       header_data.get("CHALLENGE", ""),
                "category":        header_data.get("CATEGORY", ""),
                "difficulty":      header_data.get("DIFFICULTY", ""),
                "key_technique":   header_data.get("KEY_TECHNIQUE", ""),
                "key_functions_str": header_data.get("KEY_FUNCTIONS", "")
            }

            batch_docs.append(content)
            batch_metas.append(metadata)
            batch_ids.append(doc_id)

            if len(batch_docs) >= 100:
                flush_batch()

        flush_batch()  # flush remaining

        total_count = self.collection.count()
        print(f"[BinExplain KB] Added {new_count} new writeups. Total: {total_count}")

        
    def find_similar_writeups(self, binary_analysis: dict, n_results: int = 3) -> list:
        try:
            # 1. Build search query from binary_analysis dict:
            query_str = build_rag_query(binary_analysis)
            
            # 2. Use sentence-transformers to encode the query
            if self.model is None:
                from sentence_transformers import SentenceTransformer
                self.model = SentenceTransformer("all-MiniLM-L6-v2")
            query_vector = self.model.encode(query_str).tolist()
            
            # 3. Query ChromaDB for n_results most similar documents
            results = self.collection.query(
                query_embeddings=[query_vector],
                n_results=n_results
            )
            
            # 4. Return list of dicts
            if not results or not results.get("ids") or len(results["ids"]) == 0:
                return []
                
            out = []
            ids = results["ids"][0]
            metadatas = results.get("metadatas", [[]])[0]
            documents = results.get("documents", [[]])[0]
            distances = results.get("distances", [[]])[0]
            
            threshold = 0.55
            
            for i in range(len(ids)):
                doc_id = ids[i]
                metadata = metadatas[i] if i < len(metadatas) and metadatas[i] else {}
                document = documents[i] if i < len(documents) and documents[i] else ""
                distance = distances[i] if i < len(distances) else 1.0
                
                # Conversion for L2 distance (or cosine distance in [0, 2])
                similarity_score = 1.0 - (distance / 2.0)
                similarity_score = max(0.0, min(1.0, similarity_score))
                
                # Filter out results with low similarity
                if similarity_score < threshold:
                    continue
                    
                # Excerpt: first 350 chars of body text
                parts = document.split("---", 2)
                body_text = parts[2].strip() if len(parts) >= 3 else document.strip()
                snippet = body_text[:350]
                
                title = metadata.get("challenge")
                if not title:
                    title = doc_id
                    
                out.append({
                    "title": title,
                    "url": metadata.get("url", ""),
                    "category": metadata.get("category", ""),
                    "key_technique": metadata.get("key_technique", ""),
                    "snippet": snippet,
                    "similarity_score": float(similarity_score)
                })
                
            return out
        except Exception as e:
            # If no results or error, return empty list (never crash)
            print(f"[BinExplain KB] Error finding similar writeups: {e}")
            return []
            
    def format_for_ai_context(self, results: list) -> str:
        if not results:
            return ""
            
        output_parts = ["=== SIMILAR CTF CHALLENGES FOUND IN KNOWLEDGE BASE ==="]
        for r in results:
            part = (
                f"Challenge: {r['title']} | Category: {r['category']}\n"
                f"Technique used: {r['key_technique']}\n"
                f"Similarity Score: {r.get('similarity_score', 0.0):.2f}\n"
                f"Source: {r['url']}\n"
                f"Excerpt: {r['snippet']}\n"
                "---"
            )
            output_parts.append(part)
            
        output_parts.append("Use the above as reference. Adapt advice specifically to the binary being analyzed now.")
        
        return "\n\n".join(output_parts)
        
    def update_from_scraper(self):
        self.load_all_walkthroughs()
        print("[BinExplain KB] Updated from scraper.")
