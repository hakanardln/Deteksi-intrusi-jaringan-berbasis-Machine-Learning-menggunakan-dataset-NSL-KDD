import docx
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import nsdecls, qn

def set_cell_background(cell, fill_hex):
    tcPr = cell._tc.get_or_add_tcPr()
    shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{fill_hex}"/>')
    tcPr.append(shd)

def set_cell_margins(cell, top=120, bottom=120, left=160, right=160):
    tcPr = cell._tc.get_or_add_tcPr()
    tcMar = parse_xml(f'<w:tcMar {nsdecls("w")}><w:top w:w="{top}" w:type="dxa"/><w:bottom w:w="{bottom}" w:type="dxa"/><w:left w:w="{left}" w:type="dxa"/><w:right w:w="{right}" w:type="dxa"/></w:tcMar>')
    tcPr.append(tcMar)

def create_styled_table(doc, headers, data, col_widths=None, header_bg="1B365D", alt_bg="F2F5F9"):
    table = doc.add_table(rows=len(data) + 1, cols=len(headers))
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.autofit = False

    # Header Row
    hdr_cells = table.rows[0].cells
    for i, title in enumerate(headers):
        hdr_cells[i].text = title
        set_cell_background(hdr_cells[i], header_bg)
        set_cell_margins(hdr_cells[i], top=140, bottom=140, left=180, right=180)
        p = hdr_cells[i].paragraphs[0]
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        for run in p.runs:
            run.font.bold = True
            run.font.color.rgb = RGBColor(255, 255, 255)
            run.font.name = "Calibri"
            run.font.size = Pt(10)

    # Data Rows
    for r_idx, row_data in enumerate(data):
        row_cells = table.rows[r_idx + 1].cells
        bg_color = alt_bg if r_idx % 2 == 1 else "FFFFFF"
        for c_idx, cell_value in enumerate(row_data):
            row_cells[c_idx].text = str(cell_value)
            set_cell_background(row_cells[c_idx], bg_color)
            set_cell_margins(row_cells[c_idx], top=100, bottom=100, left=160, right=160)
            p = row_cells[c_idx].paragraphs[0]
            p.alignment = WD_ALIGN_PARAGRAPH.LEFT
            for run in p.runs:
                run.font.name = "Calibri"
                run.font.size = Pt(9.5)

    # Set widths if specified
    if col_widths:
        for row in table.rows:
            for idx, width in enumerate(col_widths):
                row.cells[idx].width = width

    # Set borders
    tblPr = table._tbl.tblPr
    borders = parse_xml(
        f'<w:tblBorders {nsdecls("w")}>'
        f'<w:top w:val="single" w:sz="4" w:space="0" w:color="CCCCCC"/>'
        f'<w:bottom w:val="single" w:sz="6" w:space="0" w:color="1B365D"/>'
        f'<w:insideH w:val="single" w:sz="4" w:space="0" w:color="E0E0E0"/>'
        f'<w:insideV w:val="none"/>'
        f'<w:left w:val="none"/>'
        f'<w:right w:val="none"/>'
        f'</w:tblBorders>'
    )
    tblPr.append(borders)
    doc.add_paragraph() # space after table
    return table

def add_callout(doc, text, title="CATATAN PENTING UJIAN", border_color="D9381E", bg_color="FFF4F2"):
    tbl = doc.add_table(rows=1, cols=1)
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    tbl.autofit = False
    tbl.rows[0].cells[0].width = Inches(6.5)
    cell = tbl.rows[0].cells[0]
    set_cell_background(cell, bg_color)
    set_cell_margins(cell, top=140, bottom=140, left=200, right=160)
    
    # Left border only
    tcPr = cell._tc.get_or_add_tcPr()
    borders = parse_xml(
        f'<w:tcBorders {nsdecls("w")}>'
        f'<w:top w:val="none"/>'
        f'<w:bottom w:val="none"/>'
        f'<w:right w:val="none"/>'
        f'<w:left w:val="single" w:sz="24" w:space="0" w:color="{border_color}"/>'
        f'</w:tcBorders>'
    )
    tcPr.append(borders)
    
    p = cell.paragraphs[0]
    p.paragraph_format.space_before = Pt(2)
    p.paragraph_format.space_after = Pt(2)
    r_title = p.add_run(f"⚠️ {title}: ")
    r_title.bold = True
    r_title.font.name = "Calibri"
    r_title.font.size = Pt(10)
    r_title.font.color.rgb = RGBColor(180, 40, 20)
    
    r_text = p.add_run(text)
    r_text.font.name = "Calibri"
    r_text.font.size = Pt(10)
    doc.add_paragraph()

def build_docx():
    doc = docx.Document()
    
    # Page setup
    sections = doc.sections
    for section in sections:
        section.top_margin = Inches(0.8)
        section.bottom_margin = Inches(0.8)
        section.left_margin = Inches(0.9)
        section.right_margin = Inches(0.9)

    # Styles
    styles = doc.styles
    normal_style = styles['Normal']
    normal_style.font.name = 'Calibri'
    normal_style.font.size = Pt(10.5)
    normal_style.font.color.rgb = RGBColor(40, 40, 40)
    normal_style.paragraph_format.line_spacing = 1.15
    normal_style.paragraph_format.space_after = Pt(4)

    # Document Title
    title_p = doc.add_paragraph()
    title_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    title_p.paragraph_format.space_before = Pt(0)
    title_p.paragraph_format.space_after = Pt(2)
    r_title = title_p.add_run("RANGKUMAN LENGKAP UJIAN OBJEKTIF\nAI UNTUK KEAMANAN (AI FOR SECURITY)")
    r_title.bold = True
    r_title.font.size = Pt(16)
    r_title.font.color.rgb = RGBColor(27, 54, 93) # Navy

    sub_p = doc.add_paragraph()
    sub_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    sub_p.paragraph_format.space_after = Pt(16)
    r_sub = sub_p.add_run("Mata Kuliah: Kecerdasan Buatan untuk Keamanan (KSI251525) | Dosen: Zuliar Efendi, M.Kom.\nProgram Studi: Keamanan Sistem Informasi (KSI) - Politeknik Negeri Bengkalis")
    r_sub.italic = True
    r_sub.font.size = Pt(9.5)
    r_sub.font.color.rgb = RGBColor(100, 100, 100)

    # Divider line
    div_p = doc.add_paragraph()
    div_p.paragraph_format.space_after = Pt(12)
    pBdr = parse_xml(f'<w:pBdr {nsdecls("w")}><w:bottom w:val="single" w:sz="12" w:space="1" w:color="1B365D"/></w:pBdr>')
    div_p._p.get_or_add_pPr().append(pBdr)

    # 1. PETA BESAR
    h1 = doc.add_heading("1. PETA BESAR ALUR PEMBELAJARAN (PROJECT-BASED LEARNING)", level=1)
    h1.style.font.color.rgb = RGBColor(27, 54, 93)
    
    p = doc.add_paragraph()
    p.add_run("Alur mata kuliah ini dirancang dalam 6 siklus bertahap:\n").bold = True
    r_flow = p.add_run("M1 (Rumusan Masalah)  ➔  M2 (Dataset)  ➔  M3 (EDA)  ➔  M4 (Preprocessing)  ➔  M5 (Modeling)  ➔  M6 (Evaluasi)")
    r_flow.bold = True
    r_flow.font.color.rgb = RGBColor(30, 100, 160)
    
    add_callout(
        doc,
        "Proyek AI for Security TIDAK dimulai dari memilih algoritma canggih, melainkan dimulai dari masalah keamanan yang jelas dan ketersediaan data yang valid.",
        title="KAIDAH UTAMA PEMBELAJARAN"
    )

    # 2. RANGKUMAN PER MINGGU & KORELASI TUGAS
    h2 = doc.add_heading("2. RANGKUMAN MATERI PER MINGGU & KORELASI TUGAS", level=1)
    h2.style.font.color.rgb = RGBColor(27, 54, 93)

    # MINGGU 1
    doc.add_heading("A. Pertemuan 1: Konsep Dasar AI Biasa vs AI for Security", level=2)
    p = doc.add_paragraph("Berdasarkan materi pengantar dan Tugas P1 individu, berikut perbandingan esensial yang sangat sering muncul di soal teori objektif:")
    
    headers_ai = ["Aspek Pembanding", "AI Biasa (General AI)", "AI for Security (Keamanan)"]
    data_ai = [
        ["Fokus Utama", "Efisiensi, automasi, generate konten, kemudahan pengguna.", "Deteksi anomali, klasifikasi serangan/malware, mitigasi, dan automasi respons insiden."],
        ["Karakteristik Data", "Teks natural, gambar/video media sosial, preferensi belanja.", "Log server/firewall, packet capture (.pcap), flow trafik jaringan, binary/opcode malware."],
        ["Toleransi Kesalahan", "Relatif toleran/fleksibel (salah rekomendasi lagu dampaknya rendah).", "Sangat kritis: FP membebani analis SOC (alert fatigue), sedangkan FN menyebabkan kebocoran data."],
        ["Sifat Lingkungan", "Statis atau berubah alami secara organik.", "Adversarial (Bermusuhan): Penyerang secara aktif memanipulasi input (evasion attack) untuk mengecoh model."]
    ]
    create_styled_table(doc, headers_ai, data_ai, [Inches(1.5), Inches(2.5), Inches(2.5)])

    # MINGGU 2
    doc.add_heading("B. Pertemuan 2: Problem Formulation & Security Dataset", level=2)
    p = doc.add_paragraph("Materi Minggu 2 berfokus pada titik awal keputusan proyek:")
    p_b1 = doc.add_paragraph(style='List Bullet')
    p_b1.add_run("Merumuskan Masalah: ").bold = True
    p_b1.add_run("Mengubah isu keamanan menjadi pertanyaan analitik yang terukur dan dapat diuji dengan data.")
    p_b2 = doc.add_paragraph(style='List Bullet')
    p_b2.add_run("Kriteria Dataset Valid: ").bold = True
    p_b2.add_run("Wajib memiliki fitur (karakteristik koneksi), label target yang jelas, dan konteks keamanan.")
    p_b3 = doc.add_paragraph(style='List Bullet')
    p_b3.add_run("Target Model: ").bold = True
    p_b3.add_run("Harus selaras dengan keputusan yang akan diambil oleh analis keamanan (SOC Analyst).")

    p = doc.add_paragraph()
    p.add_run("Korelasi Nyata Tugas P2 Kelompok (Proyek NSL-KDD):\n").bold = True
    p.add_run("• Judul Proyek: Deteksi Intrusi Jaringan Berbasis Machine Learning menggunakan Dataset NSL-KDD.\n"
              "• Alasan memilih NSL-KDD: Merupakan versi perbaikan dari KDD Cup 99 yang telah dibersihkan dari baris duplikat/redundansi tinggi, sehingga model tidak bias ke record yang sering muncul.\n"
              "• Ukuran Data: Data Latih (KDDTrain+) = 125.973 baris; Data Uji (KDDTest+) = 22.544 baris.\n"
              "• Fitur: 41 fitur bawaan (durasi, protocol_type, service, flag, src_bytes, dst_bytes, count, dll).\n"
              "• Target Prediksi: Biner (Normal vs Attack) dan Multiclass (Normal, DoS, Probe, R2L, U2R).\n"
              "• Tantangan Utama: Class Imbalance parah pada serangan R2L dan U2R.")

    # MINGGU 3
    doc.add_heading("C. Pertemuan 3: Exploratory Data Analysis (EDA) pada Data Keamanan", level=2)
    p = doc.add_paragraph("EDA bertujuan mengenali pola data mentah sebelum pemodelan. 4 fokus pemeriksaan:")
    doc.add_paragraph("1. Struktur Data & Data Dictionary: Mengenal tipe data tiap fitur (numerik atau kategorikal).\n"
                      "2. Missing Values: Cek apakah sensor/pencatat log gagal merekam sebagian data.\n"
                      "3. Duplikasi Baris: Rekaman ganda yang tidak memberikan informasi baru dan membuat bias.\n"
                      "4. Distribusi Label & Outlier: Mengecek rasio ketimpangan kelas dan persebaran data ekstrem.")
    
    add_callout(
        doc,
        "JANGAN PERNAH menghapus outlier pada data keamanan secara sembarangan! Anomali atau serangan siber sering kali muncul sebagai data ekstrem (misalnya transfer byte mendadak super besar saat DoS/exfiltration).",
        title="JEBAKAN UJIAN TENTANG OUTLIER"
    )

    # MINGGU 4
    doc.add_heading("D. Pertemuan 4: Data Preprocessing untuk AI Security", level=2)
    p = doc.add_paragraph("Preprocessing menentukan apakah model dapat dipercaya di dunia nyata:")
    
    headers_prep = ["Langkah Preprocessing", "Tindakan Standar", "Penerapan pada Tugas Kelompok P4"]
    data_prep = [
        ["Pembersihan (Cleaning)", "Imputasi median untuk numerik (kebal outlier), modus untuk kategori. Jangan menebak label!", "Dikonfirmasi missing value = 0 dan duplikasi = 0 pada NSL-KDD."],
        ["Penanganan Outlier Skewed", "Transformasi logaritmik log1p untuk fitur right-skewed ekstrem.", "Fitur duration, src_bytes, dst_bytes dibuatkan kolom log1p tambahan."],
        ["Encoding Kategorikal", "One-Hot Encoding untuk nominal; Label Encoding hanya jika ordinal.", "OHE pada 3 kolom nominal: protocol_type, service, flag."],
        ["Scaling Numerik", "StandardScaler (mean=0, std=1) atau MinMaxScaler.", "StandardScaler pada 38 fitur numerik."],
        ["Pencegahan Data Leakage", "Split train-test SEBELUM fit transformer. Buang metadata/kunci jawaban.", "Kolom difficulty di-drop (metadata pembuat); attack_category di-drop dari X."],
        ["Pipeline", "Gabungkan ColumnTransformer + Classifier agar reproducible.", "Total dihasilkan 125 fitur dalam pipeline; smoke test akurasi internal 99,9%."]
    ]
    create_styled_table(doc, headers_prep, data_prep, [Inches(1.8), Inches(2.3), Inches(2.4)])

    # MINGGU 5
    doc.add_heading("E. Pertemuan 5: Pemilihan Algoritma & Confusion Matrix", level=2)
    p = doc.add_paragraph("Panduan pemilihan 1 algoritma untuk proyek:")
    
    headers_algo = ["Algoritma", "Karakteristik & Alasan Memilih", "Kapan Paling Cocok?"]
    data_algo = [
        ["Decision Tree", "Mudah dibaca menyerupai aturan if-else, transparan.", "Dosen/analis membutuhkan penjelasan logis sederhana."],
        ["Random Forest", "Ensemble banyak pohon; stabil terhadap noise dan outlier; tidak mudah overfit.", "Data tabular dengan banyak fitur campuran (PILIHAN TUGAS P5)."],
        ["Logistic Regression", "Model linear berbasis peluang, sangat cepat dilatih, koefisien mudah dibaca.", "Baseline awal; saat hubungan fitur dan target cukup sederhana."],
        ["KNN", "Melihat kemiripan jarak data tetangga terdekat.", "Data skala kecil dengan fitur yang sudah dinormalisasi."],
        ["SVM", "Mencari batas pemisah (hyperplane) maksimal antar kelas.", "Data tidak terlalu besar dan kelas dapat dipisahkan tegas."],
        ["Gradient Boosting", "Ensemble boosting di mana pohon baru mengoreksi residual pohon sebelumnya.", "Data tabular dengan pola non-linear rumit (PILIHAN TUGAS P6)."]
    ]
    create_styled_table(doc, headers_algo, data_algo, [Inches(1.5), Inches(2.7), Inches(2.3)])

    # 3. BEDAH CONFUSION MATRIX
    h3 = doc.add_heading("3. BEDAH TUNTAS CONFUSION MATRIX & METRIK EVALUASI", level=1)
    h3.style.font.color.rgb = RGBColor(27, 54, 93)

    p = doc.add_paragraph("Dalam keamanan siber: ")
    p.add_run("Kelas Positif = Attack/Serangan (yang ingin ditemukan), Kelas Negatif = Normal/Aman.").bold = True
    
    headers_cm = ["Matriks", "Prediksi Positif (Attack)", "Prediksi Negatif (Normal)"]
    data_cm = [
        ["Aktual Positif (Attack)", "True Positive (TP)\nSerangan berhasil dideteksi ✅", "False Negative (FN)\nSerangan LOLOS tanpa alarm ❌ (FATAL!)"],
        ["Aktual Negatif (Normal)", "False Positive (FP)\nAlarm Palsu / False Alarm ⚠️ (Ops)", "True Negative (TN)\nTrafik normal dibiarkan lewat ✅"]
    ]
    create_styled_table(doc, headers_cm, data_cm, [Inches(1.8), Inches(2.3), Inches(2.4)], header_bg="2B547E")

    p = doc.add_paragraph()
    p.add_run("Dampak Nyata di Industri Keamanan:\n").bold = True
    p.add_run("• False Negative (FN): Celah keamanan paling berbahaya! Serangan siber menyusup tanpa disadari analis, berakibat kebocoran data (data breach).\n"
              "• False Positive (FP): Mengakibatkan alert fatigue, yaitu analis SOC kelelahan menangani alarm bodong sehingga beban operasional membengkak.")

    doc.add_heading("Rumus-Rumus Metrik Evaluasi:", level=2)
    doc.add_paragraph(
        "1. Accuracy = (TP + TN) / (TP + TN + FP + FN)\n"
        "   Hati-hati: Menyesatkan pada data yang tidak seimbang (Class Imbalance)!\n\n"
        "2. Precision = TP / (TP + FP)\n"
        "   Pertanyaan analitis: 'Dari seluruh alarm yang berbunyi, berapa persen yang benar-benar serangan?'\n"
        "   Diprioritaskan saat: Biaya penanganan alarm palsu sangat mahal / ingin menekan FP.\n\n"
        "3. Recall (Detection Rate / Sensitivity) = TP / (TP + FN)\n"
        "   Pertanyaan analitis: 'Dari total seluruh serangan yang masuk, berapa persen yang berhasil ditangkap sistem?'\n"
        "   Diprioritaskan saat: Keamanan maksimal di mana tidak boleh ada serangan yang lolos / ingin menekan FN.\n\n"
        "4. F1-Score = 2 * (Precision * Recall) / (Precision + Recall)\n"
        "   Rata-rata harmonis ketika ingin keseimbangan antara presisi dan recall."
    )

    # 4. FAKTA DATA & HASIL EKSPERIMEN TUGAS
    h4 = doc.add_heading("4. FAKTA DATA & HASIL EKSPERIMEN TUGAS KELOMPOK", level=1)
    h4.style.font.color.rgb = RGBColor(27, 54, 93)

    p = doc.add_paragraph("Hasil perbandingan Gradient Boosting (GB) vs Logistic Regression (LR) pada data uji resmi KDDTest+ (22.544 baris: 12.833 Attack & 9.711 Normal):")

    headers_comp = ["Metrik Pengujian", "Gradient Boosting (GB)", "Logistic Regression (LR)", "Interpretasi Hasil Ujian"]
    data_comp = [
        ["Accuracy", "80,66%", "73,61%", "GB unggul +7,05 poin."],
        ["Precision (Attack)", "97,17%", "91,08%", "Dari 100 alert: GB hanya 3 salah, LR 9 salah."],
        ["Recall (Tolak Ukur Utama)", "68,00%", "59,46%", "GB menangkap 1.096 serangan lebih banyak daripada LR."],
        ["F1-Score", "80,01%", "71,95%", "GB unggul +8,06 poin."],
        ["False Negative (FN)", "4.107 serangan", "5.203 serangan", "Serangan yang lolos pada GB jauh lebih sedikit."],
        ["False Positive (FP)", "254 alarm", "747 alarm", "Alarm palsu LR hampir 3 kali lipat lebih banyak."],
        ["Total Loss (FN + FP)", "4.361", "5.950", "Celah kesalahan LR lebih besar 1.589 koneksi."],
        ["ROC-AUC", "0,9446", "0,7792", "Kemampuan pemisahan probabilitas GB jauh superior."],
        ["Waktu Pelatihan", "42,6 detik", "2,5 detik", "LR jauh lebih cepat (keunggulan model linear)."]
    ]
    create_styled_table(doc, headers_comp, data_comp, [Inches(1.8), Inches(1.5), Inches(1.5), Inches(1.7)])

    p = doc.add_paragraph()
    p.add_run("Poin Analisis Studi Kasus Lanjutan:\n").bold = True
    p.add_run("1. Mengapa GB Menang? Pola serangan NSL-KDD tidak dapat dipisahkan secara linear. Diperlukan model non-linear dengan pohon bertingkat.\n"
              "2. Kelemahan Terbesar: Ada pada kategori R2L (Recall GB hanya 14,77% dan LR hampir 0 yaitu 0,42%).\n"
              "3. Serangan Baru (Unseen): Recall terhadap serangan yang pernah dilatih mencapai 78,72%, tetapi anjlok ke 42,03% pada varian serangan baru di data uji.\n"
              "4. Fitur Paling Berpengaruh: Fitur src_bytes (bobot 0,5354) adalah penentu terbesar pada Gradient Boosting.\n"
              "5. Pengaruh Threshold: Menurunkan ambang keputusan dari 0,5 ke 0,1 menaikkan Recall GB dari 68,00% ke 80,01% (FN turun drastis dari 4.107 ke 2.565).")

    # 5. CHEAT SHEET UJIAN
    h5 = doc.add_heading("5. CHEAT-SHEET UJIAN OBJEKTIF: KUNCI HAFALAN CEPAT", level=1)
    h5.style.font.color.rgb = RGBColor(27, 54, 93)

    headers_cheat = ["Pertanyaan Soal Objektif", "Jawaban Kunci yang Harus Dipilih"]
    data_cheat = [
        ["Ciri khas lingkungan AI Security?", "Adversarial (penyerang aktif mencari celah mengecoh model)."],
        ["Kesalahan model paling berbahaya bagi keamanan?", "False Negative (FN) karena serangan lolos tanpa deteksi."],
        ["Dampak negatif False Positive (FP) yang tinggi?", "Alert Fatigue (analis SOC kelelahan menangani alarm bodong)."],
        ["Mengapa akurasi tidak cukup untuk mengevaluasi IDS?", "Karena Class Imbalance (data normal jauh mendominasi serangan)."],
        ["Sikap terhadap data outlier saat EDA security?", "Dianalisis konteksnya, jangan langsung dibuang (bisa jadi itu serangan)."],
        ["Tujuan penggunaan parameter stratify=y saat split?", "Menjaga proporsi kelas normal dan attack tetap sama di train dan test."],
        ["Kapan terjadi Data Leakage saat preprocessing?", "Saat fit scaler/encoder dilakukan sebelum train-test split, atau ada fitur bocoran seperti difficulty."],
        ["Encoding yang wajib untuk fitur protocol/service?", "One-Hot Encoding (karena nominal, tidak punya urutan)."],
        ["Mengapa NSL-KDD dibuat menggantikan KDD Cup 99?", "Menghilangkan data duplikat/redundansi agar model tidak bias."],
        ["Metrik utama jika tidak ingin ada serangan lolos?", "Recall (Detection Rate / Sensitivity)."],
        ["Metrik utama jika ingin setiap alert pasti akurat?", "Precision."],
        ["Cara cepat menaikkan deteksi serangan (Recall) tanpa melatih ulang model?", "Menurunkan threshold probabilitas keputusan (misal dari 0,5 ke 0,1)."]
    ]
    create_styled_table(doc, headers_cheat, data_cheat, [Inches(3.2), Inches(3.3)], header_bg="D9381E", alt_bg="FFF9F8")

    out_path = r"d:\AI for Security\RANGKUMAN_UJIAN_AI_FOR_SECURITY.docx"
    doc.save(out_path)
    print("DOCX created successfully at:", out_path)

if __name__ == "__main__":
    build_docx()
