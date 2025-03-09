from langchain_community.document_loaders import JSONLoader, CSVLoader
from langchain_chroma import Chroma
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_huggingface.embeddings import HuggingFaceEmbeddings
from langchain_community.embeddings import HuggingFaceInferenceAPIEmbeddings
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain.prompts import PromptTemplate
from langchain.chains import LLMChain
from langchain.llms import HuggingFacePipeline
from langchain.schema import Document

from langchain_google_genai import ChatGoogleGenerativeAI, GoogleGenerativeAIEmbeddings
import json

# Step 1: LLM Setup (Gemini)
llm = ChatGoogleGenerativeAI(model="gemini-1.5-pro", google_api_key=GOOGLE_API_KEY)

# Action extraction chain
action_prompt = PromptTemplate(
    input_variables=["text"],
    template="Extract attacker actions from this threat report snippet as a concise list, one action per line, no markers or extra text: '{text}'"
)
action_chain = LLMChain(llm=llm, prompt=action_prompt)

# Step 2: Load and Process MITRE JSON
def load_mitre_techniques(file_path):
    with open(file_path, "r") as f:
        mitre_data = json.load(f)
    techniques = [obj for obj in mitre_data["objects"] if obj["type"] == "attack-pattern"]
    documents = []
    for t in techniques:
        content = f"Technique: {t['name']}\nDescription: {t.get('description', 'No description available')}"
        metadata = {
            "technique_id": t["external_references"][0]["external_id"],
            "technique_name": t["name"]
        }
        documents.append(Document(page_content=content, metadata=metadata))
    return documents

mitre_file = "/content/enterprise-attack.json"
raw_docs = load_mitre_techniques(mitre_file)

text_splitter = RecursiveCharacterTextSplitter(
    chunk_size=500,
    chunk_overlap=50,
    separators=["\n\n", "\n", ".", " "]
)
mitre_docs = []
for doc in raw_docs:
    if len(doc.page_content) > 500:
        split_docs = text_splitter.split_documents([doc])
        mitre_docs.extend(split_docs)
    else:
        mitre_docs.append(doc)

# Embed MITRE data into Chroma
#embeddings = HuggingFaceEmbeddings(model_name="sentence-transformers/all-mpnet-base-v2")
embeddings = HuggingFaceInferenceAPIEmbeddings(
    api_key="your-api-key", model_name="sentence-transformers/all-MiniLM-l6-v2"
)
#embeddings = GoogleGenerativeAIEmbeddings(model="models/text-embedding-004", google_api_key=GOOGLE_API_KEY)

mitre_store = Chroma.from_documents(
    documents=mitre_docs,
    embedding=embeddings,
    persist_directory="mitredb"
)

# Step 3: Load and Process CSV Rules
rule_file = "/content/rules.csv"  # Update this path
loader = CSVLoader(file_path=rule_file, encoding='latin-1', source_column="Rule Description")
rule_docs = loader.load()

for doc in rule_docs:
    rule_id = doc.metadata.get("Rule ID", "Unknown")
    if "rule_id" not in doc.metadata:
        doc.metadata["rule_id"] = rule_id

rule_store = Chroma.from_documents(
    documents=rule_docs,
    embedding=embeddings,
    persist_directory="rulesdb"
)

# Step 4: MITRE Mapping Function
def map_to_mitre(action, vector_store):
    docs = vector_store.similarity_search_with_score(action, k=1)
    top_doc, score = docs[0]
    return {
        "technique_id": top_doc.metadata["technique_id"],
        "technique_name": top_doc.metadata["technique_name"],
        "score": score
    }

# Step 5: LLM-Based Detection Evaluation
detection_prompt = PromptTemplate(
    input_variables=["action", "rule"],
    template="Given an attacker action: '{action}' and a detection rule: '{rule}', determine if the rule can detect the action. Answer with 'Yes' or 'No' followed by a brief explanation."
)
detection_chain = LLMChain(llm=llm, prompt=detection_prompt)

def evaluate_detection(action, rule_store):
    retrieved_rules = rule_store.similarity_search_with_score(action, k=1)
    top_rule, score = retrieved_rules[0]
    rule_content = top_rule.page_content
    result = detection_chain.run({"action": action, "rule": rule_content})
    verdict, explanation = result.split("\n", 1) if "\n" in result else (result, "No explanation provided")
    return f"{verdict} - Rule: '{rule_content}' (Rule ID: {top_rule.metadata['rule_id']}, Score: {score:.4f})\nExplanation: {explanation}"

# Step 6: Full Pipeline
def process_report(report):
    # Extract actions
    actions = action_chain.run(report)
    action_list = [line.strip() for line in actions.split("\n") if line.strip()]

    # Map to MITRE
    mappings = {}
    for action in action_list:
        mappings[action] = map_to_mitre(action, mitre_store)

    # Evaluate detection
    results = {}
    for action in action_list:
        results[action] = evaluate_detection(action, rule_store)

    # Presentable output
    print("\n=== Threat Report Analysis ===\n")
    print("Actions Extracted:")
    for i, action in enumerate(action_list, 1):
        print(f"{i}. {action}")

    print("\nMITRE ATT&CK Mappings:")
    for action, mapping in mappings.items():
        print(f"- {action}:")
        print(f"  Technique: {mapping['technique_id']} ({mapping['technique_name']})")
        print(f"  Confidence Score: {mapping['score']:.4f}")

    print("\nDetection Evaluation:")
    for action, result in results.items():
        print(f"- {action}:")
        for line in result.split("\n"):
            print(f"  {line}")

    # Return raw data for further use if needed
    return {"actions": action_list, "mappings": mappings, "results": results}

# Test
report = "The attacker executed a malicious script via PowerShell and downloaded a file."
output = process_report(report)
print("Output:", output)
