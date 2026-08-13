package com.alberto.tfm.vulnerabilidades.export;

import com.alberto.tfm.vulnerabilidades.dto.DashboardStatsResponse;
import com.lowagie.text.Document;
import com.lowagie.text.DocumentException;
import com.lowagie.text.Element;
import com.lowagie.text.Font;
import com.lowagie.text.FontFactory;
import com.lowagie.text.HeaderFooter;
import com.lowagie.text.PageSize;
import com.lowagie.text.Paragraph;
import com.lowagie.text.Phrase;
import com.lowagie.text.Rectangle;
import com.lowagie.text.pdf.PdfPCell;
import com.lowagie.text.pdf.PdfPTable;
import com.lowagie.text.pdf.PdfWriter;
import org.springframework.stereotype.Component;

import java.awt.Color;
import java.io.IOException;
import java.io.OutputStream;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Map;

/**
 * Genera un informe en PDF con el resumen de estadísticas del Dashboard
 * (mismos datos que se muestran en pantalla, en formato tabular ya que el
 * PDF no reproduce las gráficas interactivas).
 */
@Component
public class DashboardPdfReportWriter {

    private static final DateTimeFormatter TIMESTAMP = DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm");

    private static final Color TEXT = new Color(0x1F, 0x29, 0x37);
    private static final Color MUTED = new Color(0x6B, 0x72, 0x80);
    private static final Color BORDER = new Color(0xE5, 0xE7, 0xEB);
    private static final Color LABEL_BG = new Color(0xF3, 0xF4, 0xF6);
    private static final Color PRIMARY = new Color(0x00, 0xB8, 0x94);

    private static final Font TITLE_FONT = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 20, TEXT);
    private static final Font SUBTITLE_FONT = FontFactory.getFont(FontFactory.HELVETICA, 10, MUTED);
    private static final Font SECTION_FONT = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 13, TEXT);
    private static final Font STAT_VALUE_FONT = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 18, PRIMARY);
    private static final Font STAT_LABEL_FONT = FontFactory.getFont(FontFactory.HELVETICA, 9, MUTED);
    private static final Font LABEL_FONT = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 9, MUTED);
    private static final Font VALUE_FONT = FontFactory.getFont(FontFactory.HELVETICA, 9, TEXT);

    public void write(DashboardStatsResponse stats, OutputStream out) throws IOException {
        Document document = new Document(PageSize.A4, 40, 40, 44, 44);

        try {
            PdfWriter.getInstance(document, out);

            HeaderFooter footer = new HeaderFooter(new Phrase("", SUBTITLE_FONT), true);
            footer.setBorder(Rectangle.NO_BORDER);
            footer.setAlignment(Element.ALIGN_CENTER);
            document.setFooter(footer);

            document.open();
            writeHeader(document);
            writeStatTiles(document, stats);
            writeSection(document, "Por severidad", toTable(stats.getBySeverity()));
            writeSection(document, "Por categoría", toTable(stats.getByCategory()));
            writeSection(document, "Vulnerabilidades por año de publicación", toTable(stats.getByYear()));
            writeTopFrameworks(document, stats);
            writeLatestVulnerability(document, stats);
        } catch (DocumentException e) {
            throw new IOException("No se pudo generar el PDF del dashboard", e);
        } finally {
            if (document.isOpen()) {
                document.close();
            }
        }
    }

    private void writeHeader(Document document) throws DocumentException {
        Paragraph title = new Paragraph("Informe del Dashboard", TITLE_FONT);
        title.setSpacingAfter(4f);
        document.add(title);

        Paragraph meta = new Paragraph(
                "Generado el " + TIMESTAMP.format(LocalDateTime.now()), SUBTITLE_FONT);
        meta.setSpacingAfter(18f);
        document.add(meta);
    }

    private void writeStatTiles(Document document, DashboardStatsResponse stats) throws DocumentException {
        PdfPTable table = new PdfPTable(3);
        table.setWidthPercentage(100);
        table.setSpacingAfter(20f);

        table.addCell(statCell(stats.getTotalVulnerabilities(), "Vulnerabilidades totales"));
        table.addCell(statCell(stats.getAddedLast7Days(), "Añadidas últimos 7 días"));
        table.addCell(statCell(stats.getAddedLast30Days(), "Añadidas último mes"));

        document.add(table);
    }

    private PdfPCell statCell(long value, String label) {
        PdfPTable inner = new PdfPTable(1);
        inner.addCell(borderlessCell(formatNumber(value), STAT_VALUE_FONT, Element.ALIGN_CENTER));
        inner.addCell(borderlessCell(label, STAT_LABEL_FONT, Element.ALIGN_CENTER));

        PdfPCell cell = new PdfPCell(inner);
        cell.setBackgroundColor(LABEL_BG);
        cell.setBorderColor(BORDER);
        cell.setPadding(10f);
        return cell;
    }

    private PdfPCell borderlessCell(String text, Font font, int alignment) {
        PdfPCell cell = new PdfPCell(new Phrase(text, font));
        cell.setBorder(Rectangle.NO_BORDER);
        cell.setHorizontalAlignment(alignment);
        cell.setPaddingBottom(2f);
        return cell;
    }

    private void writeSection(Document document, String title, PdfPTable table) throws DocumentException {
        Paragraph heading = new Paragraph(title, SECTION_FONT);
        heading.setSpacingBefore(6f);
        heading.setSpacingAfter(8f);
        document.add(heading);
        document.add(table);
    }

    private PdfPTable toTable(Map<String, Long> counts) throws DocumentException {
        PdfPTable table = new PdfPTable(new float[] { 3f, 1f });
        table.setWidthPercentage(100);
        table.setSpacingAfter(18f);

        table.addCell(labelCell("Nombre"));
        table.addCell(labelCell("Cantidad"));

        for (Map.Entry<String, Long> entry : counts.entrySet()) {
            table.addCell(valueCell(ExportText.sanitize(entry.getKey())));
            table.addCell(valueCell(formatNumber(entry.getValue())));
        }

        return table;
    }

    private void writeTopFrameworks(Document document, DashboardStatsResponse stats) throws DocumentException {
        PdfPTable table = new PdfPTable(new float[] { 3f, 1f });
        table.setWidthPercentage(100);
        table.setSpacingAfter(18f);

        table.addCell(labelCell("Framework / tecnología"));
        table.addCell(labelCell("Cantidad"));

        for (DashboardStatsResponse.NameCount entry : stats.getTopFrameworks()) {
            table.addCell(valueCell(ExportText.sanitize(entry.getName())));
            table.addCell(valueCell(formatNumber(entry.getCount())));
        }

        writeSection(document, "Top frameworks/tecnologías", table);
    }

    private void writeLatestVulnerability(Document document, DashboardStatsResponse stats) throws DocumentException {
        DashboardStatsResponse.LatestVulnerability latest = stats.getLatestVulnerability();
        if (latest == null) {
            return;
        }

        Paragraph heading = new Paragraph("Última vulnerabilidad añadida", SECTION_FONT);
        heading.setSpacingBefore(6f);
        heading.setSpacingAfter(8f);
        document.add(heading);

        PdfPTable table = new PdfPTable(new float[] { 1f, 3f });
        table.setWidthPercentage(100);

        table.addCell(labelCell("Nombre"));
        table.addCell(valueCell(ExportText.sanitize(latest.getName())));
        table.addCell(labelCell("Severidad"));
        table.addCell(valueCell(ExportText.sanitize(latest.getSeverity())));
        table.addCell(labelCell("Categoría"));
        table.addCell(valueCell(ExportText.sanitize(latest.getCategory())));
        table.addCell(labelCell("Fecha"));
        table.addCell(valueCell(latest.getCreatedAt() == null ? "" : TIMESTAMP.format(latest.getCreatedAt())));
        table.addCell(labelCell("Descripción"));
        table.addCell(valueCell(ExportText.sanitize(latest.getDescription())));

        document.add(table);
    }

    private PdfPCell labelCell(String label) {
        PdfPCell cell = new PdfPCell(new Phrase(label, LABEL_FONT));
        cell.setBackgroundColor(LABEL_BG);
        cell.setBorderColor(BORDER);
        cell.setPadding(6f);
        return cell;
    }

    private PdfPCell valueCell(String value) {
        PdfPCell cell = new PdfPCell(new Phrase(value.isBlank() ? "—" : value, VALUE_FONT));
        cell.setBorderColor(BORDER);
        cell.setPadding(6f);
        return cell;
    }

    private String formatNumber(long value) {
        return String.format("%,d", value).replace(',', '.');
    }
}
