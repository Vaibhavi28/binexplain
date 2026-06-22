import os
os.environ["TOKENIZERS_PARALLELISM"] = "false"

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
        txt_files = [f for f in os.listdir(walkthroughs_dir) if f.endswith(".txt")]
        
        for filename in txt_files:
            filepath = os.path.join(walkthroughs_dir, filename)
            doc_id = os.path.splitext(filename)[0]
            
            # Skip if document ID already exists in ChromaDB (no duplicates)
            existing = self.collection.get(ids=[doc_id])
            if existing and existing.get("ids") and len(existing["ids"]) > 0:
                continue
                
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except Exception as e:
                print(f"[BinExplain KB] Error reading file {filepath}: {e}")
                continue
                
            # Parse the header (lines between --- markers at top)
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
                        
            # Extract: SOURCE, URL, CHALLENGE, CATEGORY, DIFFICULTY, PROTECTIONS, KEY_FUNCTIONS, KEY_TECHNIQUE
            source = header_data.get("SOURCE", "")
            url = header_data.get("URL", "")
            challenge = header_data.get("CHALLENGE", "")
            category = header_data.get("CATEGORY", "")
            difficulty = header_data.get("DIFFICULTY", "")
            key_technique = header_data.get("KEY_TECHNIQUE", "")
            key_functions_str = header_data.get("KEY_FUNCTIONS", "")
            
            # Add to ChromaDB:
            # - document = full file text
            # - metadata = {source, url, challenge, category, difficulty, key_technique, key_functions_str}
            # - id = filename without .txt extension
            metadata = {
                "source": source,
                "url": url,
                "challenge": challenge,
                "category": category,
                "difficulty": difficulty,
                "key_technique": key_technique,
                "key_functions_str": key_functions_str
            }
            
            self.collection.add(
                documents=[content],
                metadatas=[metadata],
                ids=[doc_id]
            )
            new_count += 1
            
        total_count = self.collection.count()
        print(f"[BinExplain KB] Added {new_count} new writeups. Total: {total_count}")
        
    def find_similar_writeups(self, binary_analysis: dict, n_results: int = 3) -> list:
        try:
            # 1. Build search query from binary_analysis dict:
            ctf_category_dict = binary_analysis.get("ctf_category") or {}
            if isinstance(ctf_category_dict, dict):
                ctf_category = ctf_category_dict.get("category", "")
            else:
                ctf_category = ""
                
            patterns = binary_analysis.get("patterns") or {}
            if isinstance(patterns, dict):
                dangerous_functions = patterns.get("dangerous_functions", [])
            else:
                dangerous_functions = []
            if not isinstance(dangerous_functions, list):
                dangerous_functions = []
                
            checksec = binary_analysis.get("checksec") or {}
            if not isinstance(checksec, dict):
                checksec = {}
            nx = checksec.get("nx", False)
            pie = checksec.get("pie", False)
            canary = checksec.get("canary", False)
            filename = binary_analysis.get("filename", "")
            
            query_str = f"{ctf_category} {' '.join(dangerous_functions[:5])} NX={nx} PIE={pie} canary={canary}"
            
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
            
            for i in range(len(ids)):
                doc_id = ids[i]
                metadata = metadatas[i] if i < len(metadatas) and metadatas[i] else {}
                document = documents[i] if i < len(documents) and documents[i] else ""
                distance = distances[i] if i < len(distances) else 1.0
                
                # Cosine similarity score = 1.0 - distance (clamped to [0, 1])
                similarity_score = 1.0 - distance
                similarity_score = max(0.0, min(1.0, similarity_score))
                
                # 5. Only include results where similarity_score > 0.3
                if similarity_score <= 0.3:
                    continue
                    
                # Excerpt: first 400 chars of body text
                parts = document.split("---", 2)
                body_text = parts[2].strip() if len(parts) >= 3 else document.strip()
                snippet = body_text[:400]
                
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
            # 6. If no results or error, return empty list (never crash)
            print(f"[BinExplain KB] Error finding similar writeups: {e}")
            return []
            
    def format_for_ai_context(self, results: list) -> str:
        # 1. If results is empty, return ""
        if not results:
            return ""
            
        # 2. Build this exact string
        output_parts = ["=== SIMILAR CTF CHALLENGES FOUND IN KNOWLEDGE BASE ==="]
        for r in results:
            part = (
                f"Challenge: {r['title']} | Category: {r['category']}\n"
                f"Technique used: {r['key_technique']}\n"
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
