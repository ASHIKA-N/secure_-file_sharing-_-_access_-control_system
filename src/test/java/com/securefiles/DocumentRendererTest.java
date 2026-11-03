package com.securefiles;

import static org.junit.jupiter.api.Assertions.*;

import com.securefiles.exception.AppException;
import com.securefiles.service.DocumentRenderer;
import java.io.*;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.*;
import org.apache.pdfbox.pdmodel.encryption.*;
import org.apache.pdfbox.pdmodel.font.*;
import org.apache.pdfbox.text.PDFTextStripper;
import org.junit.jupiter.api.Test;

class DocumentRendererTest {
  static byte[] pdf(int pages) throws Exception {
    try (PDDocument doc = new PDDocument()) {
      for (int i = 0; i < pages; i++) {
        PDPage page = new PDPage();
        doc.addPage(page);
        try (PDPageContentStream out = new PDPageContentStream(doc, page)) {
          out.beginText();
          out.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA), 12);
          out.newLineAtOffset(50, 700);
          out.showText("Original page " + (i + 1));
          out.endText();
        }
      }
      ByteArrayOutputStream bytes = new ByteArrayOutputStream();
      doc.save(bytes);
      return bytes.toByteArray();
    }
  }

  @Test
  void watermarkEveryPageIdentityAndOriginalUnchanged() throws Exception {
    byte[] original = pdf(2);
    DocumentRenderer renderer = new DocumentRenderer();
    byte[] changed =
        renderer.watermark(
            original,
            "Chitra Long Recipient Name\n"
                + "chitra@example.test\n"
                + "UTC 2026-11-02T12:00:00Z\n"
                + "Reference test-reference");
    try (PDDocument doc = Loader.loadPDF(changed)) {
      String text = new PDFTextStripper().getText(doc);
      assertEquals(2, text.split("chitra@example.test", -1).length - 1);
      assertTrue(text.contains("test-reference"));
    }
    try (PDDocument doc = Loader.loadPDF(original)) {
      assertFalse(new PDFTextStripper().getText(doc).contains("chitra@example.test"));
    }
    var rendered =
        renderer.page("application/pdf", original, 1, "Viewer identity\nUTC 2026-11-02T12:00:00Z");
    assertEquals(2, rendered.pages());
    assertTrue(rendered.bytes().length > 100);
    for (String format : new String[] {"png", "jpeg"}) {
      var tiny = new java.awt.image.BufferedImage(2, 2, java.awt.image.BufferedImage.TYPE_INT_RGB);
      var out = new ByteArrayOutputStream();
      javax.imageio.ImageIO.write(tiny, format, out);
      var page =
          renderer.page(
              format.equals("png") ? "image/png" : "image/jpeg",
              out.toByteArray(),
              0,
              "Recipient identity\nUTC session time");
      var image = javax.imageio.ImageIO.read(new ByteArrayInputStream(page.bytes()));
      assertTrue(
          image.getWidth() >= 300 && image.getHeight() >= 150,
          "Tiny images need room for a readable identity overlay");
    }
  }

  @Test
  void malformedEncryptedAndExcessPagesFailClearly() throws Exception {
    var renderer = new DocumentRenderer();
    assertThrows(
        AppException.class, () -> renderer.watermark("%PDF-1.4 invalid %%EOF".getBytes(), "name"));
    assertThrows(AppException.class, () -> renderer.page("application/pdf", pdf(41), 0, "name"));
    try (PDDocument doc = Loader.loadPDF(pdf(1))) {
      doc.protect(
          new StandardProtectionPolicy(
              "owner-private-password", "user-private-password", new AccessPermission()));
      var out = new ByteArrayOutputStream();
      doc.save(out);
      assertThrows(AppException.class, () -> renderer.watermark(out.toByteArray(), "name"));
    }
    try (PDDocument doc = Loader.loadPDF(pdf(1))) {
      var form = new org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm(doc);
      doc.getDocumentCatalog().setAcroForm(form);
      var signatureField = new org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField(form);
      signatureField.setPartialName("Approval");
      signatureField.setValue(
          new org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature());
      form.getFields().add(signatureField);
      assertFalse(doc.getSignatureDictionaries().isEmpty());
      var out = new ByteArrayOutputStream();
      doc.save(out);
      assertThrows(AppException.class, () -> renderer.watermark(out.toByteArray(), "name"));
    }
  }
}
