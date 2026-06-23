import os
import sys
import pytest
from unittest.mock import MagicMock, patch

# Ensure backend directory is in path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import main
from main import is_low_quality_response, app
from fastapi.testclient import TestClient

client = TestClient(app)


def test_is_low_quality_response():
    # Less than 50 chars -> True
    assert is_low_quality_response("") is True
    assert is_low_quality_response("Too short") is True

    # High quality response -> False
    assert is_low_quality_response(
        "I can see a GDB output showing a crash at address 0x080484b4 in main. "
        "The buffer gets overflown, suggesting you should investigate the offset."
    ) is False

    # Low quality response with generic phrases and length < 150 -> True
    low_quality_text = "I can see an image. This appears to be a CTF challenge, but I don't have enough information."
    assert len(low_quality_text) < 150
    assert is_low_quality_response(low_quality_text) is True

    # Low quality content but length >= 150 -> False (passes length threshold)
    long_low_quality = (
        "I can see an image. This appears to be a CTF challenge, but I don't have enough information. "
        "Please provide more context or upload a cleaner screenshot with better resolution, "
        "and tell me what commands you have run so far."
    )
    assert len(long_low_quality) >= 150
    assert is_low_quality_response(long_low_quality) is False


@patch("main._is_testing")
@patch("main.GEMINI_API_KEY", "dummy-gemini-key")
@patch("main.GROQ_API_KEY", "dummy-groq-key")
@patch("main.OPENAI_API_KEY", "dummy-openai-key")
@patch("main.ANTHROPIC_API_KEY", "dummy-claude-key")
def test_analyze_image_fallback_chain(mock_is_testing):
    # Make _is_testing return False so that endpoint executes fallback chain
    mock_is_testing.return_value = False

    # Mock the clients
    mock_gemini_client = MagicMock()
    # Gemini returns a low quality response, so it should fall back
    mock_gemini_response = MagicMock()
    mock_gemini_response.text = "I can see an image. This appears to be a terminal." # Low quality (generic + short)
    mock_gemini_client.models.generate_content.return_value = mock_gemini_response

    # Groq returns a low quality response (e.g. too short), so it should fall back
    mock_groq_client = MagicMock()
    mock_groq_completion = MagicMock()
    mock_groq_completion.choices = [MagicMock()]
    mock_groq_completion.choices[0].message.content = "Short response" # Low quality (< 50 chars)
    mock_groq_client.chat.completions.create.return_value = mock_groq_completion

    # OpenAI returns a high quality response, so chain should stop here
    mock_openai_client = MagicMock()
    mock_openai_completion = MagicMock()
    mock_openai_completion.choices = [MagicMock()]
    mock_openai_completion.choices[0].message.content = (
        "The screenshot displays a GDB session where a segfault occurred at 0x080484a2. "
        "It was triggered during the gets call. Next step: calculate the offset using cyclic."
    )
    mock_openai_client.chat.completions.create.return_value = mock_openai_completion

    with patch("main.gemini_client", mock_gemini_client), \
         patch("groq.Groq", return_value=mock_groq_client), \
         patch("openai.OpenAI", return_value=mock_openai_client):

        # Send a mock image file
        mock_png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
        resp = client.post(
            "/analyze-image",
            files={"file": ("gdb.png", mock_png)},
            data={"context": "ret2win"},
            headers={"X-Forwarded-For": "10.9.9.9"}
        )

        assert resp.status_code == 200
        response_json = resp.json()
        assert "response" in response_json
        # Check that OpenAI was selected because Gemini and Groq returned low quality responses
        assert "GDB session where a segfault occurred at 0x080484a2" in response_json["response"]
