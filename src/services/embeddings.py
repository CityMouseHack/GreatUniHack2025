## generate embeddings

from google import genai
from google.genai import types
from google.cloud import firestore
from google.cloud.firestore_v1.vector import Vector
import firebase_admin
from firebase_admin import credentials
from firebase_admin import firestore

cred = credentials.Certificate('')

firebase_admin.initialize_app(cred)
client = genai.Client()

# group users by their location

# location, vector


class Embedder:
    def __init__(self, model_name: str):
        self.model_name = model_name
        self.client = genai.Client()

    def embed_content(self, contents):
        try:
            return(self.client.models.embed_content(
            model=self.model_name,
            contents=contents,
            config=types.EmbedContentConfig(task_type="RETRIEVAL_DOCUMENT", output_dimensionality=2048)))
        except:
            raise Exception("Error embedding content")

if __name__ == "__main__":
    texts = [
        "What is the meaning of life?",
        "What is the purpose of existence?",
        "How do I bake a cake?"]

    # Calculate cosine similarity. Higher scores = greater semantic similarity.

    embed = Embedder("gemini-embedding-001")
    embedding = embed.embed_content(texts)

    # 1. Get the firestore client
    db = firestore.client()
    collection = db.collection('messages')

    # 2. Extract the first embedding vector from the response
    doc = {
        "location": "mars",
        "embedding_field": Vector(embedding.embeddings[0].values),
    }
    collection.add(doc)
