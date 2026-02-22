package burp.privilege.ui.panel;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.privilege.model.ScanResult;
import burp.privilege.ui.table.ResultTableModel;

import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import java.awt.*;
import java.util.List;

/**
 * 结果面板
 * 显示扫描结果
 */
public class ResultPanel extends JPanel {

    private final MontoyaApi api;
    private ResultTableModel tableModel;
    private JTable resultTable;
    private JLabel statsLabel;
    private JLabel progressLabel;
    private JProgressBar progressBar;

    public ResultPanel() {
        this.api = null;
        initUI();
    }

    public ResultPanel(MontoyaApi api) {
        this.api = api;
        initUI();
    }

    public void setApi(MontoyaApi api) {
        // 可以通过此方法设置API引用
    }

    private void initUI() {
        setLayout(new BorderLayout(10, 10));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // 顶部统计面板
        JPanel topPanel = createTopPanel();
        add(topPanel, BorderLayout.NORTH);

        // 结果表格
        tableModel = new ResultTableModel();
        resultTable = new JTable(tableModel);
        resultTable.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        resultTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        resultTable.setRowHeight(22);

        // 设置列宽
        resultTable.getColumnModel().getColumn(0).setPreferredWidth(80);   // 类型
        resultTable.getColumnModel().getColumn(1).setPreferredWidth(60);   // 风险
        resultTable.getColumnModel().getColumn(2).setPreferredWidth(60);   // 方法
        resultTable.getColumnModel().getColumn(3).setPreferredWidth(300);  // URL
        resultTable.getColumnModel().getColumn(4).setPreferredWidth(80);   // 状态码
        resultTable.getColumnModel().getColumn(5).setPreferredWidth(60);   // 相似度
        resultTable.getColumnModel().getColumn(6).setPreferredWidth(100);  // 原始凭证
        resultTable.getColumnModel().getColumn(7).setPreferredWidth(100);  // 测试凭证

        JScrollPane scrollPane = new JScrollPane(resultTable);
        add(scrollPane, BorderLayout.CENTER);

        // 添加行点击事件
        resultTable.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
            @Override
            public void valueChanged(ListSelectionEvent e) {
                if (!e.getValueIsAdjusting() && resultTable.getSelectedRow() >= 0) {
                    // 双击查看详情，单击可以选择
                }
            }
        });

        // 双击查看详情
        resultTable.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent e) {
                if (e.getClickCount() == 2) {
                    viewDetail();
                }
            }
        });

        // 底部按钮面板
        JPanel buttonPanel = createButtonPanel();
        add(buttonPanel, BorderLayout.SOUTH);
    }

    private JPanel createTopPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(BorderFactory.createTitledBorder("统计信息"));

        // 统计标签
        statsLabel = new JLabel("总结果: 0 | 漏洞: 0 | 可疑: 0");
        progressLabel = new JLabel("状态: 等待开始");

        // 进度条
        progressBar = new JProgressBar(0, 100);
        progressBar.setStringPainted(true);
        progressBar.setVisible(false);

        panel.add(statsLabel);
        panel.add(progressLabel);
        panel.add(progressBar);

        return panel;
    }

    private JPanel createButtonPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        JButton clearButton = new JButton("清除结果");
        clearButton.addActionListener(e -> clearResults());

        JButton exportButton = new JButton("导出结果");
        exportButton.addActionListener(e -> exportResults());

        JButton viewButton = new JButton("查看详情");
        viewButton.addActionListener(e -> viewDetail());

        JButton sendToRepeaterButton = new JButton("发送到Repeater");
        sendToRepeaterButton.addActionListener(e -> sendToRepeater());

        panel.add(clearButton);
        panel.add(exportButton);
        panel.add(viewButton);
        panel.add(sendToRepeaterButton);

        return panel;
    }

    /**
     * 添加扫描结果
     */
    public void addResult(ScanResult result) {
        tableModel.addResult(result);
        updateStats();
    }

    /**
     * 添加多个扫描结果
     */
    public void addResults(List<ScanResult> results) {
        tableModel.addResults(results);
        updateStats();
    }

    /**
     * 清除结果
     */
    public void clearResults() {
        tableModel.clear();
        updateStats();
        resetProgress();
    }

    /**
     * 更新统计信息
     */
    private void updateStats() {
        int total = tableModel.getRowCount();
        int vuln = tableModel.getVulnerabilityCount();
        int suspicious = tableModel.getSuspiciousCount();

        statsLabel.setText(String.format("总结果: %d | 漏洞: %d | 可疑: %d", total, vuln, suspicious));
    }

    /**
     * 更新进度
     */
    public void updateProgress(int completed, int total) {
        progressBar.setVisible(true);
        progressBar.setMaximum(total);
        progressBar.setValue(completed);
        progressLabel.setText(String.format("进度: %d / %d (%.1f%%)",
                completed, total, (double) completed / total * 100));
    }

    /**
     * 重置进度
     */
    public void resetProgress() {
        progressBar.setVisible(false);
        progressBar.setValue(0);
        progressLabel.setText("状态: 等待开始");
    }

    /**
     * 设置扫描完成状态
     */
    public void setScanComplete() {
        progressBar.setVisible(false);
        progressLabel.setText("状态: 扫描完成");
    }

    /**
     * 设置扫描中状态
     */
    public void setScanning() {
        progressBar.setVisible(true);
        progressLabel.setText("状态: 扫描中...");
    }

    /**
     * 查看详情
     */
    private void viewDetail() {
        int selectedRow = resultTable.getSelectedRow();
        if (selectedRow >= 0) {
            ScanResult result = tableModel.getResultAt(selectedRow);
            showDetailDialog(result);
        } else {
            JOptionPane.showMessageDialog(this, "请先选择一个结果", "提示", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    /**
     * 显示详情对话框
     */
    private void showDetailDialog(ScanResult result) {
        JDialog dialog = new JDialog((Frame) SwingUtilities.getWindowAncestor(this), "扫描结果详情", true);
        dialog.setSize(600, 500);
        dialog.setLocationRelativeTo(this);

        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // 基本信息
        StringBuilder info = new StringBuilder();
        info.append("漏洞类型: ").append(result.getVulnTypeText()).append("\n");
        info.append("风险等级: ").append(result.getRiskLevel().getDisplayName()).append("\n");
        info.append("URL: ").append(result.getUrl()).append("\n");
        info.append("方法: ").append(result.getMethod()).append("\n");
        info.append("原始状态码: ").append(result.getOriginalStatusCode()).append("\n");
        info.append("测试状态码: ").append(result.getTestStatusCode()).append("\n");
        info.append("相似度: ").append(result.getSimilarityText()).append("\n");
        info.append("原始凭证: ").append(result.getOriginalCredentialName()).append("\n");
        info.append("测试凭证: ").append(result.getTestCredentialName()).append("\n");

        JTextArea infoArea = new JTextArea(info.toString());
        infoArea.setEditable(false);
        infoArea.setBackground(panel.getBackground());

        // 响应对比
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

        JTextArea originalResponseArea = new JTextArea(result.getOriginalResponse());
        originalResponseArea.setEditable(false);
        JScrollPane originalScrollPane = new JScrollPane(originalResponseArea);
        originalScrollPane.setBorder(BorderFactory.createTitledBorder("原始响应"));

        JTextArea testResponseArea = new JTextArea(result.getTestResponse());
        testResponseArea.setEditable(false);
        JScrollPane testScrollPane = new JScrollPane(testResponseArea);
        testScrollPane.setBorder(BorderFactory.createTitledBorder("测试响应"));

        splitPane.setTopComponent(originalScrollPane);
        splitPane.setBottomComponent(testScrollPane);
        splitPane.setDividerLocation(200);

        panel.add(infoArea, BorderLayout.NORTH);
        panel.add(splitPane, BorderLayout.CENTER);

        // 关闭按钮
        JButton closeButton = new JButton("关闭");
        closeButton.addActionListener(e -> dialog.dispose());
        panel.add(closeButton, BorderLayout.SOUTH);

        dialog.add(panel);
        dialog.setVisible(true);
    }

    /**
     * 导出结果
     */
    private void exportResults() {
        // TODO: 实现结果导出功能
        JOptionPane.showMessageDialog(this, "导出功能待实现", "提示", JOptionPane.INFORMATION_MESSAGE);
    }

    /**
     * 发送到Repeater
     */
    private void sendToRepeater() {
        int selectedRow = resultTable.getSelectedRow();
        if (selectedRow >= 0) {
            ScanResult result = tableModel.getResultAt(selectedRow);
            sendToRepeater(result);
        } else {
            JOptionPane.showMessageDialog(this, "请先选择一个结果", "提示", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    /**
     * 发送结果到Repeater
     */
    private void sendToRepeater(ScanResult result) {
        if (api == null) {
            JOptionPane.showMessageDialog(this, "API未初始化，无法发送到Repeater", "错误", JOptionPane.ERROR_MESSAGE);
            return;
        }

        // 让用户选择发送哪个请求
        String[] options = {"原始请求", "测试请求"};
        int choice = JOptionPane.showOptionDialog(this,
                "选择要发送到Repeater的请求",
                "发送到Repeater",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.QUESTION_MESSAGE,
                null,
                options,
                options[0]);

        HttpRequest requestToSend = null;
        if (choice == 0) {
            // 原始请求
            requestToSend = result.getOriginalHttpRequest();
        } else if (choice == 1) {
            // 测试请求
            requestToSend = result.getTestHttpRequest();
        }

        if (requestToSend != null) {
            try {
                api.repeater().sendToRepeater(requestToSend);
                api.logging().logToOutput("已发送请求到Repeater: " + result.getMethod() + " " + result.getUrl());
                JOptionPane.showMessageDialog(this, "请求已发送到Repeater", "成功", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception e) {
                JOptionPane.showMessageDialog(this, "发送失败: " + e.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    public ResultTableModel getTableModel() {
        return tableModel;
    }
}
