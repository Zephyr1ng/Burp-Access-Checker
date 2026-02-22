package burp.privilege.ui;

import burp.api.montoya.MontoyaApi;
import burp.privilege.model.ScanConfig;
import burp.privilege.scanner.ScanEngine;
import burp.privilege.ui.panel.ConfigPanel;
import burp.privilege.ui.panel.ControlPanel;
import burp.privilege.ui.panel.ResultPanel;

import javax.swing.*;
import java.awt.*;

/**
 * 主Tab界面
 * 插件在Burp Suite中显示的主界面
 */
public class MainTab extends JPanel {

    private final MontoyaApi api;
    private final ScanConfig config;
    private final ScanEngine scanEngine;

    private ConfigPanel configPanel;
    private ResultPanel resultPanel;
    private ControlPanel controlPanel;

    private JTabbedPane tabbedPane;

    public MainTab(MontoyaApi api) {
        this.api = api;
        this.config = new ScanConfig();
        this.scanEngine = new ScanEngine(api, config);

        initUI();
    }

    private void initUI() {
        setLayout(new BorderLayout(10, 10));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // 创建控制面板
        resultPanel = new ResultPanel(api);
        controlPanel = new ControlPanel(scanEngine, resultPanel);

        // 创建配置面板
        configPanel = new ConfigPanel(config);
        controlPanel.setConfigPanel(configPanel);

        // 创建Tab面板
        tabbedPane = new JTabbedPane();

        JPanel configWrapper = new JPanel(new BorderLayout());
        configWrapper.add(configPanel, BorderLayout.NORTH);
        configWrapper.add(new JPanel(), BorderLayout.CENTER);  // 占位

        tabbedPane.addTab("配置", configWrapper);
        tabbedPane.addTab("结果", resultPanel);

        // 添加组件
        add(controlPanel, BorderLayout.NORTH);
        add(tabbedPane, BorderLayout.CENTER);

        // 应用Burp主题
        api.userInterface().applyThemeToComponent(this);
    }

    /**
     * 获取配置面板
     */
    public ConfigPanel getConfigPanel() {
        return configPanel;
    }

    /**
     * 获取结果面板
     */
    public ResultPanel getResultPanel() {
        return resultPanel;
    }

    /**
     * 获取扫描引擎
     */
    public ScanEngine getScanEngine() {
        return scanEngine;
    }

    /**
     * 获取扫描配置
     */
    public ScanConfig getConfig() {
        return configPanel.getConfig();
    }

    /**
     * 设置扫描配置
     */
    public void setConfig(ScanConfig config) {
        configPanel.setConfig(config);
    }
}
