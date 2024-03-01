package com.mamaliang.mmpki.gmt0016;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;

public class Util {
    public static boolean flag_debug = false;
    /**
     * 字节数组转16进制
     * @param bytes 需要转换的byte数组
     * @return  转换后的Hex字符串
     */
    public static String bytesToHex(byte[] bytes) {
        StringBuffer sb = new StringBuffer();
        for(int i = 0; i < bytes.length; i++) {
            String hex = Integer.toHexString(bytes[i] & 0xFF);
            if(hex.length() < 2){
                sb.append(0);
            }
            sb.append(hex);
        }
        return sb.toString();
    }
 
    // 使用ArrayList方法
//java 合并两个byte数组
//    https://www.cnblogs.com/wisdo/p/5074434.html
    //System.arraycopy()方法
    public static byte[] byteMerger(byte[] bt1, byte[] bt2){
        byte[] bt3 = new byte[bt1.length+bt2.length];
        System.arraycopy(bt1, 0, bt3, 0, bt1.length);
        System.arraycopy(bt2, 0, bt3, bt1.length, bt2.length);
        return bt3;
    }
 
 
    public static void debug(boolean flag) {
        //System.out.println("我是一条log");
        /* 日志字体颜色 */
        flag_debug = flag;
    }
 
    public static void red(String args) {
        //System.out.println("我是一条log");
        /* 日志字体颜色 */
        if(flag_debug)
            System.out.println(Util.RED+args+Util.RESET);
    }
    public static void redxx(String args) {
        //System.out.println("我是一条log");
        /* 日志字体颜色 */
        if(flag_debug)
            System.out.print(Util.RED+args+Util.RESET);
    }
 
    public static void blue(String args) {
        //System.out.println("我是一条log");
        /* 日志字体颜色 */
        if(flag_debug)
            System.out.println(Util.BLUE+args+Util.RESET);
    }
    public static String getString(ByteBuffer buffer)
    {
        Charset charset = null;
        CharsetDecoder decoder = null;
        CharBuffer charBuffer = null;
        try
        {
            charset = Charset.forName("UTF-8");
            decoder = charset.newDecoder();
            // charBuffer = decoder.decode(buffer);//用这个的话，只能输出来一次结果，第二次显示为空
            charBuffer = decoder.decode(buffer.asReadOnlyBuffer());
            return charBuffer.toString();
        }
        catch (Exception ex)
        {
            ex.printStackTrace();
            return "";
        }
    }
 
    // Reset
    public static final String RESET = "\033[0m";  // Text Reset
 
    // Regular Colors
    public static final String WHITE = "\033[0;30m";   // WHITE
    public static final String RED = "\033[0;31m";     // RED
    public static final String GREEN = "\033[0;32m";   // GREEN
    public static final String YELLOW = "\033[0;33m";  // YELLOW
    public static final String BLUE = "\033[0;34m";    // BLUE
    public static final String PURPLE = "\033[0;35m";  // PURPLE
    public static final String CYAN = "\033[0;36m";    // CYAN
    public static final String GREY = "\033[0;37m";   // GREY
 
    // Bold
    public static final String WHITE_BOLD = "\033[1;30m";  // WHITE
    public static final String RED_BOLD = "\033[1;31m";    // RED
    public static final String GREEN_BOLD = "\033[1;32m";  // GREEN
    public static final String YELLOW_BOLD = "\033[1;33m"; // YELLOW
    public static final String BLUE_BOLD = "\033[1;34m";   // BLUE
    public static final String PURPLE_BOLD = "\033[1;35m"; // PURPLE
    public static final String CYAN_BOLD = "\033[1;36m";   // CYAN
    public static final String GREY_BOLD = "\033[1;37m";  // GREY
 
    // Underline
    public static final String WHITE_UNDERLINED = "\033[4;30m";  // WHITE
    public static final String RED_UNDERLINED = "\033[4;31m";    // RED
    public static final String GREEN_UNDERLINED = "\033[4;32m";  // GREEN
    public static final String YELLOW_UNDERLINED = "\033[4;33m"; // YELLOW
    public static final String BLUE_UNDERLINED = "\033[4;34m";   // BLUE
    public static final String PURPLE_UNDERLINED = "\033[4;35m"; // PURPLE
    public static final String CYAN_UNDERLINED = "\033[4;36m";   // CYAN
    public static final String GREY_UNDERLINED = "\033[4;37m";  // GREY
 
    // Background
    public static final String WHITE_BACKGROUND = "\033[40m";  // WHITE
    public static final String RED_BACKGROUND = "\033[41m";    // RED
    public static final String GREEN_BACKGROUND = "\033[42m";  // GREEN
    public static final String YELLOW_BACKGROUND = "\033[43m"; // YELLOW
    public static final String BLUE_BACKGROUND = "\033[44m";   // BLUE
    public static final String PURPLE_BACKGROUND = "\033[45m"; // PURPLE
    public static final String CYAN_BACKGROUND = "\033[46m";   // CYAN
    public static final String GREY_BACKGROUND = "\033[47m";  // GREY
 
    // High Intensity
    public static final String WHITE_BRIGHT = "\033[0;90m";  // WHITE
    public static final String RED_BRIGHT = "\033[0;91m";    // RED
    public static final String GREEN_BRIGHT = "\033[0;92m";  // GREEN
    public static final String YELLOW_BRIGHT = "\033[0;93m"; // YELLOW
    public static final String BLUE_BRIGHT = "\033[0;94m";   // BLUE
    public static final String PURPLE_BRIGHT = "\033[0;95m"; // PURPLE
    public static final String CYAN_BRIGHT = "\033[0;96m";   // CYAN
    public static final String GREY_BRIGHT = "\033[0;97m";  // GREY
 
    // Bold High Intensity
    public static final String WHITE_BOLD_BRIGHT = "\033[1;90m"; // WHITE
    public static final String RED_BOLD_BRIGHT = "\033[1;91m";   // RED
    public static final String GREEN_BOLD_BRIGHT = "\033[1;92m"; // GREEN
    public static final String YELLOW_BOLD_BRIGHT = "\033[1;93m";// YELLOW
    public static final String BLUE_BOLD_BRIGHT = "\033[1;94m";  // BLUE
    public static final String PURPLE_BOLD_BRIGHT = "\033[1;95m";// PURPLE
    public static final String CYAN_BOLD_BRIGHT = "\033[1;96m";  // CYAN
    public static final String GREY_BOLD_BRIGHT = "\033[1;97m"; // GREY
 
    // High Intensity backgrounds
    public static final String WHITE_BACKGROUND_BRIGHT = "\033[0;100m";// WHITE
    public static final String RED_BACKGROUND_BRIGHT = "\033[0;101m";// RED
    public static final String GREEN_BACKGROUND_BRIGHT = "\033[0;102m";// GREEN
    public static final String YELLOW_BACKGROUND_BRIGHT = "\033[0;103m";// YELLOW
    public static final String BLUE_BACKGROUND_BRIGHT = "\033[0;104m";// BLUE
    public static final String PURPLE_BACKGROUND_BRIGHT = "\033[0;105m"; // PURPLE
    public static final String CYAN_BACKGROUND_BRIGHT = "\033[0;106m";  // CYAN
    public static final String GREY_BACKGROUND_BRIGHT = "\033[0;107m";   // GREY
 
    public static void main(String[] args) {
        String str = new String();
        for (int i = 0; i < args.length; i++) {
            System.out.println(args[i]);
            str += args[i];
        }
        System.out.println(str);
    }
}