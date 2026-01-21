add_rules('mode.debug', 'mode.release')

add_requires('argparse v3.2')
add_requires('nfcpp', {configs = {crapto1 = true}})

set_languages('c++23')
set_warnings('all', 'extra')

target('nfc-staticnested')
    set_kind('binary')
    add_includedirs('src')
    add_packages(
        'argparse',
        'nfcpp'
    )
    add_files(
        'src/common/*.cpp',
        'src/tools/nfc-staticnested/*.cpp'
    )

target('nfc-isen')
    set_kind('binary')
    add_includedirs('src')
    add_files(
        'src/tools/nfc-isen/*.cpp'
    )

package('nfcpp', function () 
    set_sourcedir('/home/neko/Desktop/workspaces/local/nfcpp')
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
