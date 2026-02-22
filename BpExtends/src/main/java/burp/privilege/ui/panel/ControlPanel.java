package burp.privilege.ui.panel;

import burp.privilege.scanner.ScanEngine;

import javax.swing.*;
import java.awt.*;

/**
 * 控制面板
 * 提供开始、暂停、停止等控制按钮
 */
public class ControlPanel extends JPanel {

    private final ScanEngine scanEngine;
    private final ResultPanel resultPanel;
    private ConfigPanel configPanel;

    private JButton startButton;
    private JButton pauseButton;
    private JButton stopButton;

    public ControlPanel(ScanEngine scanEngine, ResultPanel resultPanel) {
        this.scanEngine = scanEngine;
        this.resultPanel = resultPanel;

        initUI();
        setupListeners();
    }

    private void initUI() {
        setLayout(new FlowLayout(FlowLayout.LEFT, 10, 5));
        setBorder(BorderFactory.createTitledBorder("扫描控制"));

        startButton = new JButton("开始扫描");
        pauseButton = new JButton("暂停");
        stopButton = new JButton("停止");

        pauseButton.setEnabled(false);
        stopButton.setEnabled(false);

        add(startButton);
        add(pauseButton);
        add(stopButton);
    }

    private void setupListeners() {
        startButton.addActionListener(e -> startScan());
        pauseButton.addActionListener(e -> pauseScan());
        stopButton.addActionListener(e -> stopScan());

        // 监听扫描引擎进度
        scanEngine.addProgressListener(new ScanEngine.ScanProgressListener() {
            @Override
            public void onProgress(int completed, int total) {
                SwingUtilities.invokeLater(() -> {
                    resultPanel.updateProgress(completed, total);
                });
            }

            @Override
            public void onResultFound(burp.privilege.model.ScanResult result) {
                SwingUtilities.invokeLater(() -> {
                    resultPanel.addResult(result);
                });
            }

            @Override
            public void onScanComplete() {
                SwingUtilities.invokeLater(() -> {
                    resultPanel.setScanComplete();
                    updateButtonStates(false);
                });
            }
        });
    }

    private void startScan() {
        if (!scanEngine.isRunning()) {
            // 开始新扫描
            scanEngine.startScan();
            resultPanel.setScanning();
            updateButtonStates(true);
            // 扫描开始后更新原始Cookie显示
            if (configPanel != null) {
                SwingUtilities.invokeLater(() -> configPanel.updateOriginalCookieDisplay());
            }
        } else if (scanEngine.isPaused()) {
            // 恢复扫描
            scanEngine.resumeScan();
            resultPanel.setScanning();
            updateButtonStates(true);
        }
    }

    private void pauseScan() {
        scanEngine.pauseScan();
        startButton.setText("继续");
        pauseButton.setEnabled(false);
    }

    private void stopScan() {
        scanEngine.stopScan();
        resultPanel.setScanComplete();
        updateButtonStates(false);
        startButton.setText("开始扫描");
    }

    private void updateButtonStates(boolean scanning) {
        startButton.setEnabled(!scanning || scanEngine.isPaused());
        pauseButton.setEnabled(scanning && !scanEngine.isPaused());
        stopButton.setEnabled(scanning);

        if (!scanning) {
            startButton.setText("开始扫描");
        } else if (!scanEngine.isPaused()) {
            startButton.setText("继续");
        }
    }

    public void setConfigPanel(ConfigPanel configPanel) {
        this.configPanel = configPanel;
    }
}
