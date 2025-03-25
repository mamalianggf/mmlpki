package com.mamaliang.mmpki.util;

import org.apache.commons.configuration2.PropertiesConfiguration;
import org.apache.commons.configuration2.builder.fluent.Configurations;
import org.apache.commons.configuration2.ex.ConfigurationException;

public class PropertiesUtil {

    private static final PropertiesConfiguration propertiesConfiguration;

    static {
        Configurations configs = new Configurations();
        // 从classpath根目录读取
        try {
            propertiesConfiguration = configs.properties("application.properties");
        } catch (ConfigurationException e) {
            throw new RuntimeException(e);
        }
    }

    public static String getString(String keyPath) {
        return propertiesConfiguration.getString(keyPath);
    }
}
