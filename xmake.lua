add_rules('mode.debug', 'mode.release', 'mode.releasedbg')

add_requires('argparse v3.2')
add_requires('cpptrace v1.0.4')
add_requires('nfcpp', {configs = {crapto1 = true}})

set_languages('c++23')
set_warnings('all', 'extra')

option('nfcpp-source', {description = 'Specify custom nfcpp source dir.'})
option('is-zigcc', {description = 'Enable workarounds for zigcc.'})
option('is-brewclang', {description = 'Enable workarounds for macosx.'})
option('is-arch', {description = 'Enable workarounds for archlinux.'})

if has_config('is-zigcc') then
    -- zig will not look for packages from the host.
    add_requireconfs('**', {system = false})
    -- eudev always enables ubsan (reason unknown).
    add_requireconfs('nfcpp.libnfc.libusb-compat.libusb.eudev', {configs = {cxflags = '-fno-sanitize=undefined'}})
end

if has_config('is-arch') then
    -- archlinux uses meson to package libdwarf, and it's missing libdwarfConfig.cmake.
    add_requireconfs('cpptrace.libdwarf', {system = false})
    set_strip('none')
end

target('platform_workarounds')
    set_kind('phony')

    if is_plat('mingw') then
        -- cf https://stackoverflow.com/questions/78452682/stdprintln-print-not-working-in-winlibs-mingw-gcc-14-1
        add_syslinks('stdc++exp', {public = true})
    end
    if is_plat('macosx') then
        -- macosx release will include the runtime library (libnfc).
        add_rpathdirs('@executable_path', {public = true})
    end
    if has_config('is-brewclang') then
        -- appleclang (worst compiler) is mostly incompatible with C++23, so we had to use brewclang and statically link libc++.
        add_ldflags('-nostdlib++', {public = true})
        add_ldflags('-Wl,$(shell brew --prefix llvm)/lib/c++/libc++.a,$(shell brew --prefix llvm)/lib/c++/libc++abi.a', {public = true})
    end

target('nfc-staticnested')
    set_kind('binary')
    add_includedirs('src')
    add_packages(
        'argparse',
        'cpptrace',
        'nfcpp'
    )
    add_files(
        'src/common/*.cpp',
        'src/tools/nfc-staticnested/*.cpp'
    )
    add_deps('platform_workarounds')

target('nfc-isen')
    set_kind('binary')
    add_includedirs('src')
    add_files(
        'src/tools/nfc-isen/*.cpp'
    )
    add_deps('platform_workarounds')

package('nfcpp', function ()
    if has_config('nfcpp-source') then
        set_sourcedir(get_config('nfcpp-source'))
    else
        add_urls('https://github.com/Redbeanw44602/nfcpp.git')
    end
    add_configs('crapto1', {description = 'Enable crapto1 feature.', default = false, type = 'boolean'})
    add_deps('libnfc')
    on_load(function (package) 
        package:add('defines', 'NFCPP_ENABLE_CRAPTO1=1')
    end)
    on_install(function (package)
        local configs = {}
        table.insert(configs, '--crapto1=' .. (package:config('crapto1') and 'true' or 'false'))
        import('package.tools.xmake').install(package, configs)
    end)
end)
