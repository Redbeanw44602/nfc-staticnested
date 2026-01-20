add_rules('mode.debug', 'mode.release')

includes('../nfcpp')

add_requires('argparse v3.2')

set_version('0.1.0')

target('nfc-staticnested')
    set_kind('binary')
    set_warnings('all', 'extra')
    set_languages('c++23')
    add_includedirs('src', '../nfcpp/src')
    add_deps('nfcpp')
    add_packages('argparse')
    add_files('src/**.cpp')
