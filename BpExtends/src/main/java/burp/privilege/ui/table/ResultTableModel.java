package burp.privilege.ui.table;

import burp.privilege.model.ScanResult;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

/**
 * 扫描结果表格模型
 */
public class ResultTableModel extends AbstractTableModel {

    private final List<ScanResult> results;
    private final String[] columnNames = {
            "类型", "风险", "方法", "URL", "状态码", "相似度", "原始凭证", "测试凭证"
    };

    public ResultTableModel() {
        this.results = new ArrayList<>();
    }

    public ResultTableModel(List<ScanResult> results) {
        this.results = new ArrayList<>(results);
    }

    @Override
    public int getRowCount() {
        return results.size();
    }

    @Override
    public int getColumnCount() {
        return columnNames.length;
    }

    @Override
    public String getColumnName(int column) {
        return columnNames[column];
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return String.class;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        ScanResult result = results.get(rowIndex);

        return switch (columnIndex) {
            case 0 -> result.getVulnTypeText();
            case 1 -> result.getRiskLevel().getDisplayName();
            case 2 -> result.getMethod();
            case 3 -> result.getUrl();
            case 4 -> result.getStatusCodeText();
            case 5 -> result.getSimilarityText();
            case 6 -> result.getOriginalCredentialName();
            case 7 -> result.getTestCredentialName();
            default -> "";
        };
    }

    public ScanResult getResultAt(int rowIndex) {
        return results.get(rowIndex);
    }

    public void addResult(ScanResult result) {
        results.add(result);
        fireTableRowsInserted(results.size() - 1, results.size() - 1);
    }

    public void addResults(List<ScanResult> newResults) {
        int start = results.size();
        results.addAll(newResults);
        fireTableRowsInserted(start, results.size() - 1);
    }

    public void clear() {
        int size = results.size();
        results.clear();
        fireTableRowsDeleted(0, size - 1);
    }

    public void setResultAt(int rowIndex, ScanResult result) {
        results.set(rowIndex, result);
        fireTableRowsUpdated(rowIndex, rowIndex);
    }

    public void removeResultAt(int rowIndex) {
        results.remove(rowIndex);
        fireTableRowsDeleted(rowIndex, rowIndex);
    }

    public List<ScanResult> getResults() {
        return new ArrayList<>(results);
    }

    public void setResults(List<ScanResult> results) {
        this.results.clear();
        this.results.addAll(results);
        fireTableDataChanged();
    }

    public int getVulnerabilityCount() {
        return (int) results.stream()
                .filter(r -> r.getRiskLevel() == ScanResult.RiskLevel.HIGH ||
                           r.getRiskLevel() == ScanResult.RiskLevel.MEDIUM)
                .count();
    }

    public int getSuspiciousCount() {
        return (int) results.stream()
                .filter(r -> r.getRiskLevel() == ScanResult.RiskLevel.LOW ||
                           r.getRiskLevel() == ScanResult.RiskLevel.INFO)
                .count();
    }
}
