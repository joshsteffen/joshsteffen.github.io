---
title: "Expanding the Portal 2 Puzzle Maker's Palette"
# date: 2024-06-18T07:35:42-04:00
date: 2025-09-29T12:24:00-04:00
type: posts
draft: true
tags: ["Reverse Engineering"]
---

![](big_palette.png)

The Perpetual Testing Initiative (or PeTI) update for Portal 2 added an in-game
level editor, allowing anyone to easily create their own puzzles and share them
via the Steam Workshop.

[BEEmod](https://github.com/BEEmod/BEE2.4), the "Better Extended Editor,"
>  "allows reconfiguring Portal 2's Puzzlemaker editor to use additional items,
>  reskin maps for different eras, and configure many other aspects."

The in-game editor's palette only has thirty-two slots, all of which are
already filled by default, so making use of the additional items provided by
BEEmod can require repeatedly swapping out items and restarting the game.

That can quickly become tedious, so let's patch the editor.

## Who to patch

The Windows version of Portal 2 is probably the most used, and since it's well
supported in [Proton](https://en.wikipedia.org/wiki/Proton_(software)),
targetting it will also give us Linux support.

The relevant code is in `Portal 2/portal2/bin/client.dll`, a somewhat large
file that has been stripped of debug information. However, the [steamdb
page](https://steamdb.info/depot/623/) for the macOS-specific content[^mac]
lists an interesting file: `puzzlemaker_dll.dylib`, which contains much less
code and still has debug symbols, making the task of reverse engineering
significantly easier.

[^mac]: The macOS content can be downloaded regardless of the platform Steam is
currently running on using the `download_depot <appid> <depotid>` command in
the Steam console[^console] [^nested]. Portal 2's app ID is 620 and the depot
ID for the macOS content is 623, so the full command would be `download_depot
620 623`.

[^console]: The console can be opened by navigating to
[`steam://open/console`](steam://open/console) in a browser, or by launching
Steam with the `-console` command line flag.

[^nested]: Yes, I did just put a footnote in a footnote.

## What to patch

Doubling the width of the palette turns out to be fairly simple and
noninvasive, only requiring a handful of bytes to be changed. There are three
functions that need to be patched to achieve this. All three are virtual
methods on the `CEditorUIPalette` class, shown in this approximation of how the
original C++ code may have looked:

```cpp
class CEditorUIPalette : public CEditorUIPanel {
    // [...]
    void LoadResources() override;
    void Render() override;
    // [...]
    void UpdateSize(int width, int height) override;
    // [...]
};
```

### CEditorUIPalette::LoadResources

Buttons for the palette are created in a loop. The items are then iterated over
to initialize their corresponding buttons. The button to initialize is chosen
based on the item's position in the grid[^why-z].

[^why-z]: It's not clear why z is involved here at all, but it seems to always be zero.

```cpp
m_buttons[position.x + position.y * 4 + position.z]
```

To patch:
- Change the first loop variable to count down from 64 instead of 32
- Change the 4 in the button index calculation to 8

```diff
0x10478c12:
- c7 45 f4 20 00 00 00    mov [ebp - 0xc], 32
+ c7 45 f4 40 00 00 00    mov [ebp - 0xc], 64
...
0x10478d2a:
- 8d 04 91                lea eax, [ecx + edx*4]
+ 8d 04 d1                lea eax, [ecx + edx*8]
```

### CEditorUIPalette::UpdateSize

The positions and sizes of the buttons are set in a nested loop.

```cpp
int n = 0;
for(int row = 0; row < 8; row++) {
    x = m_mainAreaX + 6;
    for(int col = 0; col < 4; col++) {
        m_buttons[n]->SetSize(m_buttonSize, m_buttonSize);
        m_buttons[n]->SetPos(x, y);
        n++;
        x += m_buttonSize + 1;
    }
    y += m_buttonSize + 1;
}
```

The width of the white background area behind the buttons also needs to be
increased, both for aesthetics and because the palette closes when the mouse
leaves the area. It's originally set to the width of the four buttons plus five
pixels of padding on each edge and one pixel of spacing to the left of each
button[^extra-pixel].

[^extra-pixel]: The extra pixel of spacing on the left column of buttons is
cancelled by the fact that the black border on the left overlaps the white area
while the right border does not. This is also why the buttons were positioned
starting at `m_mainAreaX + 6` instead of `m_mainAreaX + 5`.


```cpp
m_mainAreaWidth = m_buttonSize * 4 + 14;
```

To patch:
- Add four more `m_buttonSize`s and four more spacing pixels
- Bump the number of columns from 4 to 8

```diff
0x10478090:
- 8d 14 bd 0e 00 00 00    lea edx, [edi*4 + 14]
+ 8d 14 fd 12 00 00 00    lea edx, [edi*8 + 18]
...
0x104780c3:
- c7 45 f0 04 00 00 00    mov [ebp - 0x10], 4
+ c7 45 f0 08 00 00 00    mov [ebp - 0x10], 8
```

### CEditorUIPalette::Render

The final change is purely cosmetic: there is a grid drawn to fill the space
between the buttons and it needs four more vertical lines.

```diff
0x10477be2:
- c7 45 e4 03 00 00 00    mov [ebp - 0x1c], 3
+ c7 45 e4 07 00 00 00    mov [ebp - 0x1c], 7
```

## Where to patch

The editor does not generally receive substantial updates, so things like the
offsets of structure fields and even the compiled code itself are unlikely to
change. However, there is more to `client.dll` than the editor, so the location
of the code we want to patch can (and often does) change.

Conveniently, the functions we need to patch are all virtual functions in
`CEditorUIPalette`, meaning they will all be stored in a virtual function table
and, at least in the case of Microsoft's Visual C++ compiler, in the same order
as their declaration in the source code, which is also unlikely to change.

The virtual function table can be located by exploiting the presence of
[run-time type information](https://en.wikipedia.org/wiki/Run-time_type_information)
(RTTI) in `client.dll` as implemented in Visual C++ and described
[here](https://blog.quarkslab.com/visual-c-rtti-inspection.html).

## How to patch

The following Python script uses RTTI to find `CEditorUIPalette`'s virtual
function table, looks up the functions to be patched at fixed offsets in the
table, and patches the binary at fixed offsets from the beginnings of those
functions. The last step in particular is not very robust, and it would probably
be a good idea to at least do some basic pattern matching to find the
instructions to patch. That said, I've been using essentially this exact script
for over a year without issues, so improving it is left as an exercise for the
reader.

<h1 style="color: red">code here</h1>

## Now what?

This is all well and good, but BEEmod still only has thirty-two palette slots.

## Delete this section? I don't know.

Thirty-two buttons are created in `LoadResources`, accounting for the 4x8 grid
of items in the palette.

```cpp
void CEditorUIPalette::LoadResources() {
    CQP2EditorViewport *viewport = GetViewport();
    unsigned int blankTexture = viewport->LoadOpenGLTexture(&BLANK_IMAGE);

    for(int i = 0; i < 32; i++) {
        CEditorUIPanel *button = g_pUIManager->CreateUIDraggableButton();
        button->SetTexture(blankTexture);
        button->SetEnabled(false);
        m_buttons.AddToTail(button);
    }

    // [...]
}
```

In `UpdateSize`, the buttons are sized based on the resolution of the
screen/window and positioned in the grid.

```cpp
void CEditorUIPalette::UpdateSize(int width, int height) {
    m_buttonSize = height / 12;
    int leftBarWidth = height / 80;
    int sidebarWidth = Max(leftBarWidth, 10);

    SetPos(0, 0);

    m_mainAreaX = sidebarWidth + leftBarWidth;

    int textWidth, textHeight;
    m_itemNameLabel->GetTextSize(&textWidth, &textHeight);
    m_mainAreaHeight = textHeight + 18 + m_buttonSize * 8;

    int y = height / 2 - m_mainAreaHeight / 2;
    m_mainAreaY = y;

    m_mainAreaWidth = m_buttonSize * 4 + 14;
    y += 5;

    int n = 0;
    for(int row = 0; row < 8; row++) {
        x = m_mainAreaX + 6;
        for(int col = 0; col < 4; col++) {
            m_buttons[n]->SetSize(m_buttonSize, m_buttonSize);
            m_buttons[n]->SetPos(x, y);
            n++;
            x += m_buttonSize + 1;
        }
        y += m_buttonSize + 1;
    }

    // [...]
}
```

## Bla

Drawing the buttons and text is handled further up in the UI system, but the
rest of the palette is drawn in `Render`. Capturing a frame in RenderDoc or
another similar tool can provide a high-level overview of each step of the
process.

Matching up the code with the observed drawing order points to

```cpp
void CEditorUIPalette::Render() {
    // [...]

    viewport->Draw2DQuadFilled(
        m_mainAreaX, m_mainAreaY,
        m_mainAreaVisibleWidth, m_mainAreaHeight,
        color
    );

    // [...]
}
```

`m_mainAreaVisibleWidth` is set in `FrameUpdate` and changes as the palette
opens and closes, but it is derived from the fully-opened width
`m_mainAreaWidth`, which itself is set in `UpdateSize` to be the width of the
four buttons plus a fixed amount of padding.

```cpp
void CEditorUIPalette::UpdateSize(int width, int height) {
    // [...]

    m_mainAreaWidth = m_buttonSize * 4 + 14;

    // [...]
}
```

If there are `n` buttons in a row, there are `n - 1` spaces between them to be
padded by `INNER_PADDING` and two outer edges to be padded by `OUTER_PADDING`.
That is,

```cpp
m_mainAreaWidth =
    m_buttonSize * n
    + INNER_PADDING * (n - 1)
    + OUTER_PADDING * 2;
```

Counting pixels shows that `OUTER_PADDING` is 5 and `INNER_PADDING` is 1. Since
`n` is 4, there should be 13 pixels of padding in total. So why is the code
adding 14?

As it turns out, the left border is drawn overlapping the white backround while
the right border is drawn one pixel to the right of it, so in the end there are
actually only `m_mainAreaWidth - 1` white pixels per row. Adjusting for this
yields

```cpp
m_mainAreaWidth =
    m_buttonSize * n
    + INNER_PADDING * (n - 1)
    + OUTER_PADDING * 2
    + 1;
```


<h3 style="color: red">
I am not responsible for any fucking up of your computer
or life caused by the use of this script.
</h3>

```python
import pefile

client_dll_path = "C:\\Program Files (x86)\\Steam\\steamapps\\common\\Portal 2\\portal2\\bin\\client.dll"

pe = pefile.PE(client_dll_path)
image = pe.get_memory_mapped_image(ImageBase=0)

def find_vftable(image, cls):
    type_descriptor = image.find(cls) - 8
    complete_object_locator = image.find(type_descriptor.to_bytes(4, "little")) - 0xC
    vftable = image.find(complete_object_locator.to_bytes(4, "little")) + 4
    return vftable


def get_vfunc_file_offset(vtable, n):
    return pe.get_offset_from_rva(pe.get_dword_at_rva(vtable + n * 4) - 0x10000000)


CEditorUIPalette_vftable = find_vftable(image, b".?AVCEditorUIPalette@@")
LoadResources = get_vfunc_file_offset(CEditorUIPalette_vftable, 0)
Render = get_vfunc_file_offset(CEditorUIPalette_vftable, 1)
UpdateSize = get_vfunc_file_offset(CEditorUIPalette_vftable, 4)

pe.close()

with open(client_dll_path, "r+b") as f:
    #
    # CEditorUIPalette::LoadResources
    #

    # number of buttons
    # - mov [ebp - 0xc], 32
    # + mov [ebp - 0xc], 64
    f.seek(LoadResources + 0x22 + 3)
    f.write(b"\x40")

    # number of columns for indexing
    # - lea eax, [ecx + edx*4]
    # + lea eax, [ecx + edx*8]
    f.seek(LoadResources + 0x13A + 2)
    f.write(b"\xd1")

    #
    # CEditorUIPalette::UpdateSize
    #

    # number of columns and padding for panel width calculation
    # - lea edx, [edi*4 + 0xe]
    # + lea edx, [edi*8 + 0x12]
    f.seek(UpdateSize + 0xA0 + 2)
    f.write(b"\xfd\x12")

    # number of columns for button placement
    # - mov [ebp - 0x10], 4
    # + mov [ebp - 0x10], 8
    f.seek(UpdateSize + 0xD3 + 3)
    f.write(b"\x08")

    #
    # CEditorUIPalette::Render
    #

    # number of vertical grid lines to draw
    # - mov [ebp - 0x1c], 3
    # + mov [ebp - 0x1c], 7
    f.seek(Render + 0x3B2 + 3)
    f.write(b"\x07")
```
