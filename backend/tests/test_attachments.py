from app.analyzers import attachments
from tests.helpers import make_email


def signals(*names):
    files = [{"name": n, "contentType": "application/octet-stream", "size": 100} for n in names]
    return [f.signal for f in attachments.analyze(make_email(attachments=files))]


def test_normal_documents_have_no_findings():
    assert signals("report.pdf", "photo.jpg", "budget.xlsx") == []


def test_executable():
    assert signals("setup.exe") == ["attachment_executable"]


def test_double_extension():
    assert signals("Invoice.PDF.exe") == ["attachment_double_extension"]


def test_trailing_dot_and_space_do_not_hide_extension():
    assert signals("invoice.exe. ") == ["attachment_executable"]


def test_right_to_left_override_trick():
    # Displayed as "invoiceexe.pdf", but the real extension is .exe
    found = signals("invoice‮fdp.exe")
    assert "attachment_hidden_extension" in found
    assert "attachment_executable" in found


def test_macro_office_file():
    assert signals("salaries.xlsm") == ["attachment_macro_office"]


def test_html_attachment():
    assert signals("secure_message.html") == ["attachment_web_page"]


def test_disk_image():
    assert signals("document.iso") == ["attachment_disk_image"]


def test_archive_is_low_risk():
    found = attachments.analyze(make_email(attachments=[{"name": "photos.zip", "size": 5}]))
    assert [f.points for f in found] == [10]


def test_file_without_extension():
    assert signals("README") == []
