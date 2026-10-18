"""Explicit console loader profiles and bounded input guidance."""
CONSOLE_PROFILES = ('switch-aarch64', 'psx-mipsel', 'gba-arm', 'dol-ppc', 'nes-nrom-6502', 'megadrive-m68k')
FORMAT_PROFILES = {'NSO': 'switch-aarch64', 'NRO': 'switch-aarch64',
                   'PSX_EXE': 'psx-mipsel', 'GBA': 'gba-arm', 'DOL': 'dol-ppc',
                   'NES': 'nes-nrom-6502', 'MEGADRIVE': 'megadrive-m68k'}


def inspect_console_input(path, head, profile=None):
    from gamedecomp.console_formats import detect_console_format, inspect_console_module
    from gamedecomp.retro_formats import detect_retro_format, inspect_retro_module
    from gamedecomp.nes_format import detect_nes, inspect_nes_module
    from gamedecomp.megadrive_format import detect_megadrive_format, inspect_megadrive_module
    name = detect_console_format(head)
    if name:
        result = inspect_console_module(path, name)
    elif detect_nes(head):
        result = inspect_nes_module(path)
        name = 'NES'
    elif detect_megadrive_format(head):
        result = inspect_megadrive_module(path)
        name = 'MEGADRIVE'
    else:
        name = detect_retro_format(head)
        if not name and profile == 'dol-ppc':
            name = 'DOL'
        if not name:
            return None
        result = inspect_retro_module(path, name)
    return dict(result, format=name, required_profile=FORMAT_PROFILES[name],
                loader_status='EXPERIMENTAL', semantic_status='UNKNOWN')


def unsupported_input_message(head):
    if head[:4] in (b'\x4f\x15\x3d\x1d', b'\x54\x14\xf5\xee'):
        return 'PlayStation SELF container detected. Upload an extracted ELF module; SELF decryption is not available.'
    if head[:4] == b'PFS0':
        return 'Nintendo PFS0 package detected. Upload an extracted NSO, NRO or ELF module; package extraction is not available.'
    if head[0x100:0x104] == b'HEAD':
        return 'Nintendo gamecard container detected. Upload an extracted executable module; XCI extraction is not available.'
    if head[0x200:0x208] == b'msft-xvd':
        return 'Xbox virtual container detected. Upload an extracted PE executable or DLL; package extraction is not available.'
    return ('Unsupported input. Use ELF, PE, WebAssembly or a supported console module/ROM. '
            'DOL requires the GameCube/Wii profile before upload. Arbitrary ROMs and disc images need a platform-specific loader.')
