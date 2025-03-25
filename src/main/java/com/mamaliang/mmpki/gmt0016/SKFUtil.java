package com.mamaliang.mmpki.gmt0016;

import com.mamaliang.mmpki.util.PropertiesUtil;
import com.sun.jna.Pointer;
import lombok.Getter;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

// todo 感觉SKFUtil和SKFLibraryWrapper重复，合并在一起，暂定成静态方法的形式
public class SKFUtil {

    @Getter
    private static SKFLibraryWrapper skf;

    static {
        skf = new SKFLibraryWrapper(PropertiesUtil.getString("usbKey.dynamicLib.name"));
    }

    public static boolean isExistContainer(String devName, String applicationName, String containerName) {
        Pointer hDev = null;
        Pointer hApplication = null;
        Pointer hContainer = null;
        try {
            hDev = skf.connectDev(devName);
            hApplication = skf.openApplication(hDev, applicationName);
            hContainer = skf.openContainer(hApplication, containerName);
            return true;
        } catch (Exception e) {
            return false;
        } finally {
            if (Objects.nonNull(skf)) {
                if (Objects.nonNull(hApplication)) {
                    skf.closeContainer(hContainer);
                }
                if (Objects.nonNull(hApplication)) {
                    skf.closeApplication(hApplication);
                }
                if (Objects.nonNull(hDev)) {
                    skf.disConnectDev(hDev);
                }
            }
        }
    }

    public static Pointer openContainer(String devName, String applicationName, String containerName) {
        Pointer hDev = null;
        Pointer hApplication = null;
        Pointer hContainer = null;
        try {
            hDev = skf.connectDev(devName);
            hApplication = skf.openApplication(hDev, applicationName);
            return skf.openContainer(hApplication, containerName);
        } finally {
            if (Objects.nonNull(skf)) {
                if (Objects.nonNull(hApplication)) {
                    skf.closeContainer(hContainer);
                }
                if (Objects.nonNull(hApplication)) {
                    skf.closeApplication(hApplication);
                }
                if (Objects.nonNull(hDev)) {
                    skf.disConnectDev(hDev);
                }
            }
        }
    }

    public static List<List<String>> listContainer() {
        Pointer hDev = null;
        Pointer hApplication = null;
        List<List<String>> containersPath = new ArrayList<>();
        try {
            List<String> devNames = skf.enumDev();
            for (String devName : devNames) {
                hDev = skf.connectDev(devNames.get(0));
                List<String> applicationNames = skf.enumApplication(hDev);
                for (String applicationName : applicationNames) {
                    hApplication = skf.openApplication(hDev, applicationNames.get(0));
                    List<String> containerNames = skf.enumContainer(hApplication);
                    for (String containerName : containerNames) {
                        containersPath.add(Arrays.asList(devName, applicationName, containerName));
                    }
                }
            }
        } finally {
            if (Objects.nonNull(skf)) {
                if (Objects.nonNull(hApplication)) {
                    skf.closeApplication(hApplication);
                }
                if (Objects.nonNull(hDev)) {
                    skf.disConnectDev(hDev);
                }
            }
        }
        return containersPath;
    }

    void createContainer(String devName, String applicationName, String containerName) {
        Pointer hDev = null;
        Pointer hApplication = null;
        try {
            hDev = skf.connectDev(devName);
            hApplication = skf.openApplication(hDev, applicationName);
            // 用户pin码
            skf.verifyPIN(hApplication, 1, PropertiesUtil.getString("usbKey.user.pin"));
            skf.createContainer(hApplication, containerName);
        } finally {
            if (Objects.nonNull(skf)) {
                if (Objects.nonNull(hApplication)) {
                    skf.closeApplication(hApplication);
                }
                if (Objects.nonNull(hDev)) {
                    skf.disConnectDev(hDev);
                }
            }
        }
    }

    void deleteContainer(String devName, String applicationName, String containerName) {
        Pointer hDev = null;
        Pointer hApplication = null;
        try {
            hDev = skf.connectDev(devName);
            hApplication = skf.openApplication(hDev, applicationName);
            // 用户pin码是12345678
            skf.verifyPIN(hApplication, 1, PropertiesUtil.getString("usbKey.user.pin"));
            skf.deleteContainer(hApplication, containerName);
        } finally {
            if (Objects.nonNull(skf)) {
                if (Objects.nonNull(hApplication)) {
                    skf.closeApplication(hApplication);
                }
                if (Objects.nonNull(hDev)) {
                    skf.disConnectDev(hDev);
                }
            }
        }
    }

}
