package burp.privilege.ui.panel;

import burp.privilege.model.AuthCredential;
import burp.privilege.model.ScanConfig;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

/**
 * 配置面板
 * 用于配置扫描参数
 */
public class ConfigPanel extends JPanel {

    private final ScanConfig config;

    // UI组件
    private JTextField domainField;
    private DefaultListModel<String> domainListModel;
    private JList<String> domainList;

    private JTextArea originalCookieDisplay;  // 原始Cookie显示区域（只读）
    private JTextField testCookieField;
    private DefaultListModel<String> testCredentialListModel;
    private JList<String> testCredentialList;

    private JSlider similaritySlider;
    private JLabel similarityLabel;
    private JSpinner threadSpinner;
    private JSpinner timeoutSpinner;

    private JCheckBox excludeStaticCheckBox;
    private JCheckBox testUnauthorizedCheckBox;

    public ConfigPanel(ScanConfig config) {
        this.config = config;
        initUI();
        loadConfig();
    }

    private void initUI() {
        setLayout(new BorderLayout(10, 10));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // 创建主面板
        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));

        // 1. 目标配置
        mainPanel.add(createTargetConfigPanel());
        mainPanel.add(Box.createVerticalStrut(10));

        // 2. 认证配置
        mainPanel.add(createAuthConfigPanel());
        mainPanel.add(Box.createVerticalStrut(10));

        // 3. 检测配置
        mainPanel.add(createScanConfigPanel());

        add(mainPanel, BorderLayout.NORTH);
    }

    /**
     * 创建目标配置面板
     */
    private JPanel createTargetConfigPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BorderLayout(5, 5));
        panel.setBorder(BorderFactory.createTitledBorder("目标配置"));

        // 域名输入
        JPanel inputPanel = new JPanel(new BorderLayout(5, 5));
        domainField = new JTextField();
        JButton addButton = new JButton("添加");
        addButton.addActionListener(e -> addDomain());

        inputPanel.add(new JLabel("目标域名:"), BorderLayout.WEST);
        inputPanel.add(domainField, BorderLayout.CENTER);
        inputPanel.add(addButton, BorderLayout.EAST);

        // 域名列表
        domainListModel = new DefaultListModel<>();
        domainList = new JList<>(domainListModel);
        JScrollPane scrollPane = new JScrollPane(domainList);
        scrollPane.setPreferredSize(new Dimension(0, 80));

        // 删除按钮
        JButton removeButton = new JButton("删除选中");
        removeButton.addActionListener(e -> removeDomain());

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        buttonPanel.add(removeButton);

        panel.add(inputPanel, BorderLayout.NORTH);
        panel.add(scrollPane, BorderLayout.CENTER);
        panel.add(buttonPanel, BorderLayout.SOUTH);

        return panel;
    }

    /**
     * 创建认证配置面板
     */
    private JPanel createAuthConfigPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(BorderFactory.createTitledBorder("认证配置"));

        // 原始凭证说明（自动提取）
        JPanel infoPanel = new JPanel(new BorderLayout(5, 5));
        infoPanel.add(new JLabel("原始Cookie："), BorderLayout.WEST);
        JLabel infoLabel = new JLabel("(扫描时自动从Proxy历史记录中提取，无需手动配置)");
        infoPanel.add(infoLabel, BorderLayout.CENTER);
        panel.add(infoPanel);

        // 原始Cookie显示区域（只读）
        originalCookieDisplay = new JTextArea(3, 50);
        originalCookieDisplay.setEditable(false);
        originalCookieDisplay.setBackground(getBackground());
        originalCookieDisplay.setText("等待扫描...扫描时会自动提取Cookie");
        JScrollPane originalScrollPane = new JScrollPane(originalCookieDisplay);
        originalScrollPane.setPreferredSize(new Dimension(0, 60));
        panel.add(originalScrollPane);

        panel.add(Box.createVerticalStrut(5));

        // 测试凭证
        JPanel testPanel = new JPanel(new BorderLayout(5, 5));
        JPanel testInputPanel = new JPanel(new BorderLayout(5, 5));
        testCookieField = new JTextField();
        JButton addTestButton = new JButton("添加测试凭证");
        addTestButton.addActionListener(e -> addTestCredential());

        testInputPanel.add(new JLabel("测试Cookie (用于越权测试):"), BorderLayout.WEST);
        testInputPanel.add(testCookieField, BorderLayout.CENTER);
        testInputPanel.add(addTestButton, BorderLayout.EAST);

        testCredentialListModel = new DefaultListModel<>();
        testCredentialList = new JList<>(testCredentialListModel);
        JScrollPane testScrollPane = new JScrollPane(testCredentialList);
        testScrollPane.setPreferredSize(new Dimension(0, 60));

        JButton removeTestButton = new JButton("删除选中");
        removeTestButton.addActionListener(e -> removeTestCredential());

        testPanel.add(testInputPanel, BorderLayout.NORTH);
        testPanel.add(testScrollPane, BorderLayout.CENTER);
        testPanel.add(removeTestButton, BorderLayout.SOUTH);

        panel.add(testPanel);

        // 未授权测试选项
        testUnauthorizedCheckBox = new JCheckBox("进行未授权访问测试", true);
        panel.add(Box.createVerticalStrut(5));
        panel.add(testUnauthorizedCheckBox);

        return panel;
    }

    /**
     * 创建扫描配置面板
     */
    private JPanel createScanConfigPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(BorderFactory.createTitledBorder("检测设置"));

        // 相似度阈值
        JPanel similarityPanel = new JPanel(new BorderLayout(5, 5));
        similaritySlider = new JSlider(50, 100, config.getSimilarityThreshold());
        similaritySlider.setMajorTickSpacing(10);
        similaritySlider.setMinorTickSpacing(5);
        similaritySlider.setPaintTicks(true);
        similaritySlider.setPaintLabels(true);
        similaritySlider.addChangeListener(e -> updateSimilarityLabel());

        similarityLabel = new JLabel("相似度阈值: " + config.getSimilarityThreshold() + "%");

        similarityPanel.add(similarityLabel, BorderLayout.WEST);
        similarityPanel.add(similaritySlider, BorderLayout.CENTER);
        panel.add(similarityPanel);

        panel.add(Box.createVerticalStrut(5));

        // 并发和超时
        JPanel optionsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        optionsPanel.add(new JLabel("并发线程:"));
        threadSpinner = new JSpinner(new SpinnerNumberModel(config.getThreadCount(), 1, 50, 1));
        optionsPanel.add(threadSpinner);

        optionsPanel.add(Box.createHorizontalStrut(20));
        optionsPanel.add(new JLabel("超时(秒):"));
        timeoutSpinner = new JSpinner(new SpinnerNumberModel(config.getTimeout(), 1, 300, 1));
        optionsPanel.add(timeoutSpinner);

        panel.add(optionsPanel);

        // 过滤选项
        excludeStaticCheckBox = new JCheckBox("排除静态资源", config.isExcludeStaticResources());
        panel.add(Box.createVerticalStrut(5));
        panel.add(excludeStaticCheckBox);

        return panel;
    }

    private void addDomain() {
        String domain = domainField.getText().trim();
        if (!domain.isEmpty()) {
            domainListModel.addElement(domain);
            config.addTargetDomain(domain);
            domainField.setText("");
        }
    }

    private void removeDomain() {
        int selectedIndex = domainList.getSelectedIndex();
        if (selectedIndex >= 0) {
            domainListModel.remove(selectedIndex);
            config.getTargetDomains().remove(selectedIndex);
        }
    }

    private void addTestCredential() {
        String cookie = testCookieField.getText().trim();
        if (!cookie.isEmpty()) {
            String name = "测试凭证" + (testCredentialListModel.size() + 1);
            testCredentialListModel.addElement(name + ": " +
                    (cookie.length() > 30 ? cookie.substring(0, 30) + "..." : cookie));

            AuthCredential credential = new AuthCredential(name, cookie);
            config.addTestCredential(credential);

            testCookieField.setText("");
        }
    }

    private void removeTestCredential() {
        int selectedIndex = testCredentialList.getSelectedIndex();
        if (selectedIndex >= 0) {
            testCredentialListModel.remove(selectedIndex);
            config.getTestCredentials().remove(selectedIndex);
        }
    }

    private void updateSimilarityLabel() {
        int value = similaritySlider.getValue();
        similarityLabel.setText("相似度阈值: " + value + "%");
    }

    /**
     * 保存配置
     */
    public void saveConfig() {
        // 相似度
        config.setSimilarityThreshold(similaritySlider.getValue());

        // 并发和超时
        config.setThreadCount((Integer) threadSpinner.getValue());
        config.setTimeout((Integer) timeoutSpinner.getValue());

        // 过滤选项
        config.setExcludeStaticResources(excludeStaticCheckBox.isSelected());
        config.setTestUnauthorizedAccess(testUnauthorizedCheckBox.isSelected());

        // 原始Cookie不需要手动保存，会自动提取
    }

    /**
     * 加载配置
     */
    private void loadConfig() {
        // 域名
        domainListModel.clear();
        for (String domain : config.getTargetDomains()) {
            domainListModel.addElement(domain);
        }

        // 测试凭证
        testCredentialListModel.clear();
        for (AuthCredential credential : config.getTestCredentials()) {
            testCredentialListModel.addElement(credential.getName() + ": " +
                    credential.getSummary());
        }

        // 相似度
        similaritySlider.setValue(config.getSimilarityThreshold());
        updateSimilarityLabel();

        // 并发和超时
        threadSpinner.setValue(config.getThreadCount());
        timeoutSpinner.setValue(config.getTimeout());

        // 过滤选项
        excludeStaticCheckBox.setSelected(config.isExcludeStaticResources());
        testUnauthorizedCheckBox.setSelected(config.isTestUnauthorizedAccess());

        // 显示原始Cookie（如果已提取）
        updateOriginalCookieDisplay();
    }

    /**
     * 更新原始Cookie显示
     */
    public void updateOriginalCookieDisplay() {
        if (config.getOriginalCredential() != null &&
            config.getOriginalCredential().getCookie() != null &&
            !config.getOriginalCredential().getCookie().isEmpty()) {
            originalCookieDisplay.setText(config.getOriginalCredential().getCookie());
            originalCookieDisplay.setToolTipText("已自动提取");
        } else {
            originalCookieDisplay.setText("等待扫描...扫描时会自动提取Cookie");
            originalCookieDisplay.setToolTipText(null);
        }
    }

    /**
     * 获取配置
     */
    public ScanConfig getConfig() {
        saveConfig();
        return config;
    }

    public void setConfig(ScanConfig config) {
        // TODO: 实现配置更新
        loadConfig();
    }
}
