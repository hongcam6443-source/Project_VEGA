#include <windows.h>
#include <stdio.h>

int main() {
    // 1. 获取整个桌面的设备上下文 (DC)
    HDC hdc = GetDC(NULL);
    if (hdc == NULL) {
        printf("Failed to get DC handle.\n");
        return 1;
    }

    // 2. 设置文本颜色为红色
    SetTextColor(hdc, RGB(255, 0, 0));

    // 3. 设置背景模式为透明，这样文字后面就不会有背景色块
    SetBkMode(hdc, TRANSPARENT);

    // 4. 设置字体（可选，为了更明显可以创建一个大字体）
    HFONT hFont = CreateFontA(
        48,                        // 字体高度
        0,                         // 字体宽度
        0,                         // 文本倾斜度
        0,                         // 基线倾斜度
        FW_BOLD,                   // 字体粗细
        FALSE,                     // 斜体
        FALSE,                     // 下划线
        FALSE,                     // 删除线
        DEFAULT_CHARSET,           // 字符集
        OUT_DEFAULT_PRECIS,        // 输出精度
        CLIP_DEFAULT_PRECIS,       // 裁剪精度
        DEFAULT_QUALITY,           // 输出质量
        DEFAULT_PITCH | FF_SWISS,  // 字体族
        "Arial"                    // 字体名称
    );
    HFONT hOldFont = (HFONT)SelectObject(hdc, hFont);

    // 5. 在屏幕上绘制文本
    // 这里简单地绘制在 (100, 100) 的位置
    const char* message = "I was here - GDI Phantom";
    TextOutA(hdc, 100, 100, message, strlen(message));

    printf("Text drawn. Check your desktop. Press Enter to exit.\n");
    getchar();

    // 6. 清理资源：恢复旧字体，删除新字体，释放 DC
    SelectObject(hdc, hOldFont);
    DeleteObject(hFont);
    ReleaseDC(NULL, hdc);

    return 0;
}