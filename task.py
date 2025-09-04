# main.py - FINAL, STATELESS, ROBUST ARCHITECTURE WITH AUTHENTICATION

import os
import json
import uuid
from datetime import datetime
from flask import Flask, jsonify, abort, request
from google.cloud import storage
from dotenv import load_dotenv
from flask_cors import CORS
import base64
import traceback

# Import the Google AI SDK
import google.generativeai as genai

# Import authentication and database modules
from flask_jwt_extended import jwt_required, get_jwt_identity
from database import db, init_database, assign_patient_to_doctor, User, get_database_uri, getconn
from auth import jwt, mail, role_required, patient_access_required, log_access, require_active_session
from auth_routes import register_auth_routes, register_user_management_routes
import sqlalchemy

load_dotenv()
app = Flask(__name__)
CORS(app)

# =================================================================
# === APPLICATION CONFIGURATION ===
# =================================================================

# Configure Flask app
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'jwt-secret-key-change-in-production')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = False  # We handle expiration with sessions

# Database configuration - Create engine with Cloud SQL connector
engine = sqlalchemy.create_engine(
    "postgresql+pg8000://",
    creator=getconn,
)
app.config['SQLALCHEMY_DATABASE_URI'] = get_database_uri()
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'creator': getconn
}

# Mail configuration for MFA
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True').lower() == 'true'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER', 'noreply@medical-app.com')

# Configure the Gemini API Key from environment variables
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if not GEMINI_API_KEY:
    raise ValueError("FATAL ERROR: GEMINI_API_KEY environment variable not found.")
genai.configure(api_key=GEMINI_API_KEY)

# Initialize extensions
jwt.init_app(app)
mail.init_app(app)
init_database(app)

# Register authentication routes
register_auth_routes(app)
register_user_management_routes(app)


# =================================================================
# === HELPER FUNCTIONS ===
# =================================================================

def fetch_all_transcripts_content(patient_id, bucket_name):
    """Fetches and concatenates the content of all transcripts for a given patient."""
    storage_client = storage.Client()
    bucket = storage_client.bucket(bucket_name)
    prefix = f"patients/{patient_id}/transcripts/"
    blobs = bucket.list_blobs(prefix=prefix)
    
    all_content = []
    for blob in blobs:
        # Skip the "directory" blob itself
        if blob.name == prefix:
            continue
        try:
            content = blob.download_as_text()
            # Include filename and creation time for context
            filename = os.path.basename(blob.name)
            all_content.append(f"--- Transcript: {filename} (Created: {blob.time_created.isoformat()}) ---\n{content}\n")
        except Exception as e:
            print(f"Warning: Could not download content for {blob.name}: {e}")
            all_content.append(f"--- Transcript: {filename} (Error loading: {e}) ---\n")
    return "\n".join(all_content)


# =================================================================
# === API ROUTES ===
# =================================================================

@app.route("/", methods=['GET'])
def home():
    """Simple home route to test application is running"""
    return jsonify({
        "status": "running",
        "message": "Medical App API is operational",
        "version": "1.0.0"
    })

@app.route("/api/transcribe", methods=['POST'])
@jwt_required()
@require_active_session
@role_required(['doctor', 'assistant'])
@log_access
def transcribe_audio_chunk():
    try:
        data = request.get_json()
        if not data or 'audio_chunk' not in data:
            abort(400, description="Invalid request, missing 'audio_chunk'.")

        audio_data_base64 = data['audio_chunk'].split(',')[1]
        
        model = genai.GenerativeModel("gemini-2.0-flash") # Using 1.5 Flash

        text_prompt = """
  1. You are given an audio file between a patient and a doctor.
  2. The language is a combination of urdu and english.
  3. Transcribe the provided audio file accurately. Also since there will be medical terms perform word level substitutions/corrections accordinly such as there may be a
  word transcribed a 10 mg Pandol but you know based on context that since it is a medical discussion therefore the term is most likely 10 mg Panadol. But do that only for
  the medical terms. Such as if some one says 10 kg of Panadol you know that it is most likely 10mg of Panadol.

  4. Translate the Urdu words to English, so that the whole transcript is in English.
  5. Transcribe the audio precisely.
  6. If the audio is unclear or contains no speech, return an empty string.
  7. Format the discussion such that each sentence either belongs to a medical professional or a patient. The sentence for medical professional should have the tag MedicalProfessional: as starting word and the one from patient should have Patient: as the starting word. A switch between the participants should be on the next line.
  8. Make sure you DO NOT PROVIDE any urdu or romanized Urdu words in your output. They MUST be translated to English.
  9. Just provide the output as mentioned above. Do not provide any additional conversational comments from the LLM model.
"""

        audio_part = {
            "mime_type": "audio/webm",
            "data": base64.b64decode(audio_data_base64)
        }
        
        response = model.generate_content([text_prompt, audio_part])
        
        newly_transcribed_text = response.text.strip()
        
        if newly_transcribed_text:
            newly_transcribed_text += " "
        
        return jsonify({"new_transcript": newly_transcribed_text})

    except Exception as e:
        error_details = traceback.format_exc()
        print(f"!!! CAUGHT EXCEPTION IN /api/transcribe: {error_details}")
        return jsonify({
            "error": "A critical error occurred on the backend.",
            "details": error_details
        }), 500


@app.route("/api/analyze", methods=['POST'])
@jwt_required()
@require_active_session
@role_required(['doctor', 'administrator'])
@patient_access_required
@log_access
def analyze_transcript():
    data = request.get_json()
    if not data or 'full_transcript' not in data:
        abort(400, description="Invalid request, missing 'full_transcript'.")

    full_transcript = data['full_transcript']
    
    try:
        model = genai.GenerativeModel("gemini-2.0-flash") # Using 1.5 Flash

        analysis_prompt = f"""
        As a medical expert AI, analyze the following medical transcript. Based on the symptoms and discussion, provide a clinical analysis.

        Transcript:
        ---
        {full_transcript}
        ---

        Based on the transcript, provide the following in a strict JSON format:
        1. "candidate_disease": A single, most likely candidate disease.
        2. "reasoning": A brief explanation (2-3 sentences) of why you chose this disease based on the symptoms mentioned in the transcript.
        3. "follow_up_questions": An array of 1 to 3 simple, direct questions that a medical professional could ask the patient to further confirm or deny the diagnosis. You don't need to 
        provide 3 questions if 1 or 2 will suffice. Your candidate disease may be different from, or same as, what the medical professional is thinking about.

        Example JSON output format:
        {{
          "candidate_disease": "Migraine",
          "reasoning": "The patient reports a throbbing headache on one side of the head, sensitivity to light, and nausea, which are classic symptoms of a migraine.",
          "follow_up_questions": [
            "Do you experience any visual disturbances, like seeing flashing lights, before the headache begins?",
            "Does the headache worsen with physical activity?",
            "Is there a history of similar headaches in your family?"
          ]
        }}

        Return ONLY the JSON object and nothing else.
        """
        
        response = model.generate_content(analysis_prompt)
        
        cleaned_response_text = response.text.strip().replace("```json", "").replace("```", "").strip()
        
        analysis_result = json.loads(cleaned_response_text)
        
        return jsonify(analysis_result)

    except json.JSONDecodeError:
        print(f"!!! JSONDECODEERROR in /api/analyze_transcript: LLM did not return valid JSON.")
        return jsonify({
            "error": "The AI analysis returned an invalid format. Please try again.",
            "details": "The AI response could not be parsed as JSON."
        }), 500
    except Exception as e:
        error_details = traceback.format_exc()
        print(f"!!! CAUGHT EXCEPTION IN /api/analyze_transcript: {error_details}")
        return jsonify({
            "error": "A critical error occurred during analysis.",
            "details": error_details
        }), 500


@app.route("/api/patient/<string:patient_id>/transcript", methods=['POST'])
@jwt_required()
@require_active_session
@role_required(['doctor', 'assistant'])
@patient_access_required
@log_access
def save_transcript(patient_id):
    BUCKET_NAME = os.getenv("GCS_BUCKET_NAME")
    if not BUCKET_NAME:
        abort(500, description="GCS_BUCKET_NAME environment variable is not set.")
    
    data = request.get_json()
    if not data or 'full_transcript' not in data:
        abort(400, description="Invalid request, missing 'full_transcript'.")
    
    full_transcript = data['full_transcript']

    try:
        storage_client = storage.Client()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"transcript_{timestamp}.txt"
        file_path = f"patients/{patient_id}/transcripts/{filename}"
        
        bucket = storage_client.bucket(BUCKET_NAME)
        blob = bucket.blob(file_path)
        
        blob.upload_from_string(full_transcript, content_type="text/plain")
        
        return jsonify({"message": "Transcript saved successfully", "file_path": file_path, "filename": filename}), 201

    except Exception as e:
        print(f"Error saving transcript for patient {patient_id}: {e}")
        abort(500, description="An error occurred while saving the transcript.")


@app.route("/api/transcriptions/<patient_id>", methods=['GET'])
@jwt_required()
@require_active_session
@role_required(['doctor', 'administrator'])
@patient_access_required
@log_access
def get_patient_transcriptions(patient_id):
    BUCKET_NAME = os.getenv("GCS_BUCKET_NAME")
    if not BUCKET_NAME:
        abort(500, description="GCS_BUCKET_NAME environment variable is not set.")

    try:
        storage_client = storage.Client()
        bucket = storage_client.bucket(BUCKET_NAME)
        prefix = f"patients/{patient_id}/transcripts/"

        transcriptions_list = []
        blobs = bucket.list_blobs(prefix=prefix)

        for blob in blobs:
            if blob.name == prefix:
                continue
            
            filename = os.path.basename(blob.name)
            transcriptions_list.append({
                "filename": filename,
                "size": blob.size,
                "time_created": blob.time_created.isoformat()
            })
        
        transcriptions_list.sort(key=lambda x: x['time_created'], reverse=True)

        return jsonify({"transcriptions": transcriptions_list})

    except Exception as e:
        print(f"Error listing transcripts for patient {patient_id}: {e}")
        abort(500, description="An error occurred while fetching patient transcriptions.")


@app.route("/api/transcriptions/<patient_id>/<filename>", methods=['GET'])
@jwt_required()
@require_active_session
@role_required(['doctor', 'administrator'])
@patient_access_required
@log_access
def get_transcription_content(patient_id, filename):
    BUCKET_NAME = os.getenv("GCS_BUCKET_NAME")
    if not BUCKET_NAME:
        abort(500, description="GCS_BUCKET_NAME environment variable is not set.")

    try:
        if ".." in filename or "/" in filename:
            abort(400, description="Invalid filename.")

        storage_client = storage.Client()
        bucket = storage_client.bucket(BUCKET_NAME)
        file_path = f"patients/{patient_id}/transcripts/{filename}"
        
        blob = bucket.blob(file_path)
        
        if not blob.exists():
            abort(404, description="Transcription file not found.")

        content = blob.download_as_text()
        
        return jsonify({"content": content})

    except Exception as e:
        print(f"Error fetching transcript content for patient {patient_id}, file {filename}: {e}")
        abort(500, description="An error occurred while fetching the transcript content.")


@app.route("/api/transcriptions/<patient_id>/<filename>", methods=['PUT'])
@jwt_required()
@require_active_session
@role_required(['doctor', 'administrator'])
@patient_access_required
@log_access
def update_transcription_content(patient_id, filename):
    BUCKET_NAME = os.getenv("GCS_BUCKET_NAME")
    if not BUCKET_NAME:
        abort(500, description="GCS_BUCKET_NAME environment variable is not set.")
    
    data = request.get_json()
    if not data or 'full_transcript' not in data:
        abort(400, description="Invalid request, missing 'full_transcript'.")
    
    full_transcript = data['full_transcript']

    try:
        if ".." in filename or "/" in filename:
            abort(400, description="Invalid filename.")

        storage_client = storage.Client()
        bucket = storage_client.bucket(BUCKET_NAME)
        file_path = f"patients/{patient_id}/transcripts/{filename}"
        
        blob = bucket.blob(file_path)

        if not blob.exists():
            abort(404, description="Transcription file to update not found.")

        blob.upload_from_string(full_transcript, content_type="text/plain")
        
        return jsonify({"message": "Transcript updated successfully", "file_path": file_path}), 200

    except Exception as e:
        print(f"Error updating transcript for patient {patient_id}, file {filename}: {e}")
        abort(500, description="An error occurred while updating the transcript.")


# =================================================================
# === THIS IS THE MODIFIED FUNCTION FOR CONTEXT-AWARE CHAT ===
# =================================================================
@app.route("/api/chat/<patient_id>", methods=['POST'])
@jwt_required()
@require_active_session
@role_required(['doctor', 'administrator'])
@patient_access_required
@log_access
def chat_with_patient_history(patient_id):
    """
    Handles chat requests, including conversation history for context.
    """
    BUCKET_NAME = os.getenv("GCS_BUCKET_NAME")
    if not BUCKET_NAME:
        abort(500, description="GCS_BUCKET_NAME environment variable is not set.")

    data = request.get_json()
    if not data or 'question' not in data:
        abort(400, description="Invalid request, missing 'question'.")

    user_question = data['question']
    # Get the conversation history, default to an empty list if not provided
    chat_history = data.get('chat_history', [])

    try:
        # 1. Fetch all transcripts content for the patient (this remains the same)
        full_history_text = fetch_all_transcripts_content(patient_id, BUCKET_NAME)
        
        if not full_history_text.strip():
            return jsonify({"answer": "No historical transcripts found for this patient to chat about."})

        # 2. Build the conversation context for the LLM
        # This will be a list of strings to join
        prompt_parts = []
        prompt_parts.append("""You are a helpful medical assistant AI. You are provided with a patient's historical medical consultation transcripts.
Your task is to answer a user's question based *only* on the provided history and the current conversation context.
If the information is not available in the history, clearly state that you cannot find the answer in the provided records.
Keep your answer concise and to the point.
""")
        
        prompt_parts.append("--- Patient Transcripts History ---")
        prompt_parts.append(full_history_text)
        prompt_parts.append("--- End of History ---")

        # Add the previous turns of the conversation
        if chat_history:
            prompt_parts.append("\n--- Current Conversation History ---")
            for turn in chat_history:
                # The frontend sends 'user' for the doctor's question
                role = "Doctor" if turn.get('role') == 'user' else "Assistant"
                prompt_parts.append(f"{role}: {turn.get('content')}")
            prompt_parts.append("--- End of Conversation History ---\n")

        # Add the new question
        prompt_parts.append("--- Doctor's New Question ---")
        prompt_parts.append(user_question)
        prompt_parts.append("--- End of Doctor's New Question ---")
        prompt_parts.append("\nAssistant's Answer:")
        
        chat_prompt = "\n".join(prompt_parts)

        # 3. Call LLM
        model = genai.GenerativeModel("gemini-2.0-flash")
        response = model.generate_content(chat_prompt)
        
        llm_answer = response.text.strip()
        
        return jsonify({"answer": llm_answer})

    except Exception as e:
        error_details = traceback.format_exc()
        print(f"!!! CAUGHT EXCEPTION IN /api/patient/{patient_id}/chat: {error_details}")
        return jsonify({
            "error": "A critical error occurred while processing the chat request.",
            "details": error_details
        }), 500
# =================================================================
# === END OF MODIFIED FUNCTION ===
# =================================================================


# ===============================================================
# === NEW ENDPOINT FOR OCR DOCUMENT ATTACHMENT ===
# ===============================================================
@app.route("/api/transcriptions/<patient_id>/<filename>/attach", methods=['POST'])
@jwt_required()
@require_active_session
@role_required(['doctor', 'administrator'])
@patient_access_required
@log_access
def attach_document_to_transcription(patient_id, filename):
    BUCKET_NAME = os.getenv("GCS_BUCKET_NAME")
    if not BUCKET_NAME:
        abort(500, "GCS_BUCKET_NAME environment variable is not set.")

    if 'document' not in request.files:
        abort(400, "No document file part in the request.")

    file = request.files['document']
    if file.filename == '':
        abort(400, "No selected file.")

    try:
        if ".." in filename or "/" in filename:
            abort(400, "Invalid filename.")
        
        # 1. OCR the image with Gemini
        image_bytes = file.read()
        image_part = {
            "mime_type": file.mimetype,
            "data": image_bytes
        }
        prompt_list = ["Extract all text from this medical document. Preserve formatting like tables and lists where possible.", image_part]
        
        model = genai.GenerativeModel("gemini-2.0-flash")
        ocr_response = model.generate_content(prompt_list)
        ocr_text = ocr_response.text.strip()

        if not ocr_text:
            return jsonify({"error": "No text could be extracted from the document."}), 400

        # 2. Prepare the text block to append
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        appended_text_block = (
            f"\n\n--- OCR Document Added: [{file.filename}] on [{timestamp}] ---\n"
            f"{ocr_text}\n"
            f"--- End of Document: [{file.filename}] ---\n\n"
        )

        # 3. Read-modify-write the transcript file in GCS
        storage_client = storage.Client()
        bucket = storage_client.bucket(BUCKET_NAME)
        file_path = f"patients/{patient_id}/transcripts/{filename}"
        blob = bucket.blob(file_path)

        if not blob.exists():
            abort(404, "Transcription file to attach to not found.")
        
        original_content = blob.download_as_text()
        new_content = original_content + appended_text_block

        blob.upload_from_string(new_content, content_type="text/plain")
        
        # 4. Return the appended block so the UI can update instantly
        return jsonify({"appended_text": appended_text_block}), 200

    except Exception as e:
        error_details = traceback.format_exc()
        print(f"!!! CAUGHT EXCEPTION IN attach_document: {error_details}")
        return jsonify({
            "error": "A critical error occurred while processing the document.",
            "details": error_details
        }), 500
# ===============================================================
# === END OF NEW ENDPOINT ===
# ===============================================================


@app.route("/api/doctors/<doctor_id>", methods=['GET'])
@jwt_required()
@require_active_session
@role_required(['administrator'])
@log_access
def get_doctor_by_id(doctor_id):
    BUCKET_NAME = os.getenv("GCS_BUCKET_NAME")
    if not BUCKET_NAME:
        abort(500, description="GCS_BUCKET_NAME environment variable is not set.")
    try:
        storage_client = storage.Client()
        bucket = storage_client.bucket(BUCKET_NAME)
        blob = bucket.blob("doctors.json")
        data_string = blob.download_as_text()
        all_doctors_data = json.loads(data_string)
        all_doctors = all_doctors_data.get("doctors", [])
        found_doctor = next((doc for doc in all_doctors if doc.get("doctor_id") == doctor_id), None)
        if found_doctor:
            found_doctor.pop("password_hash", None)
            return jsonify(found_doctor)
        else:
            abort(404, description=f"Doctor with ID {doctor_id} not found.")
    except Exception as e:
        print(f"Error fetching doctors.json: {e}")
        abort(500, description="Could not access or process doctors.json.")


@app.route("/api/doctors/<doctor_id>/patients", methods=['GET'])
@jwt_required()
@require_active_session
@role_required(['doctor', 'administrator'])
@log_access
def get_patients_for_doctor(doctor_id):
    BUCKET_NAME = os.getenv("GCS_BUCKET_NAME")
    if not BUCKET_NAME:
        abort(500, description="GCS_BUCKET_NAME is not set.")
    try:
        storage_client = storage.Client()
        bucket = storage_client.bucket(BUCKET_NAME)
        blob = bucket.blob("patients.json")
        data_string = blob.download_as_text()
        all_patients_data = json.loads(data_string)
        all_patients = all_patients_data.get("patients", [])
        filtered_patients = [p for p in all_patients if p.get("primary_doctor_id") == doctor_id]
        return jsonify({"patients": filtered_patients})
    except Exception as e:
        print(f"Error fetching patients.json: {e}")
        abort(404, description="Could not find or access patients.json.")


@app.route("/api/patients/<patient_id>", methods=['GET'])
@jwt_required()
@require_active_session
@role_required(['doctor', 'administrator'])
@patient_access_required
@log_access
def get_patient_by_id(patient_id):
    BUCKET_NAME = os.getenv("GCS_BUCKET_NAME")
    if not BUCKET_NAME:
        abort(500, description="GCS_BUCKET_NAME is not set.")
    try:
        storage_client = storage.Client()
        bucket = storage_client.bucket(BUCKET_NAME)
        blob = bucket.blob("patients.json")
        data_string = blob.download_as_text()
        all_patients_data = json.loads(data_string)
        all_patients = all_patients_data.get("patients", [])
        found_patient = next((p for p in all_patients if p.get("patient_id") == patient_id), None)
        if found_patient:
            return jsonify(found_patient)
        else:
            abort(404, description=f"Patient with ID {patient_id} not found.")
    except Exception as e:
        print(f"Error fetching patient {patient_id}: {e}")
        abort(500, description="Could not access or process patients.json.")


@app.route("/api/patients", methods=['POST'])
@jwt_required()
@require_active_session
@role_required(['doctor', 'administrator'])
@log_access
def create_patient():
    BUCKET_NAME = os.getenv("GCS_BUCKET_NAME")
    if not BUCKET_NAME:
        abort(500, description="GCS_BUCKET_NAME is not set.")
    
    new_patient_data = request.get_json()
    if not new_patient_data:
        abort(400, description="Invalid patient data.")

    try:
        storage_client = storage.Client()
        bucket = storage_client.bucket(BUCKET_NAME)
        blob = bucket.blob("patients.json")
        try:
            all_patients_string = blob.download_as_text()
            all_patients_data = json.loads(all_patients_string)
        except Exception:
            all_patients_data = {"patients": []}
        
        new_patient_data['patient_id'] = f"pat_{uuid.uuid4().hex[:12]}"
        new_patient_data['joining_date'] = datetime.today().isoformat()
        if 'comments' not in new_patient_data:
            new_patient_data['comments'] = ""

        all_patients_data["patients"].append(new_patient_data)
        blob.upload_from_string(json.dumps(all_patients_data, indent=2), content_type="application/json")

        # Link patient to current doctor if creator is a doctor; if admin, optionally link to provided primary_doctor_id
        try:
            current_user_id = int(get_jwt_identity())
            creator = User.query.get(current_user_id)
            if creator and creator.role == 'doctor':
                assign_patient_to_doctor(creator.id, new_patient_data['patient_id'])
            elif creator and creator.role == 'administrator':
                primary_doctor_id = new_patient_data.get('primary_doctor_id')
                if primary_doctor_id:
                    assign_patient_to_doctor(primary_doctor_id, new_patient_data['patient_id'])
        except Exception:
            # Do not fail patient creation if linking fails; log optionally
            pass

        return jsonify(new_patient_data), 201
    except Exception as e:
        print(f"Error creating patient: {e}")
        abort(500, description="Could not create new patient.")


if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
