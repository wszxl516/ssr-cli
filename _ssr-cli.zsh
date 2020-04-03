#compdef ssr-cli
# filename: _ssr-cli.zsh
_ssr_cli() {

    _arguments -C -s -S -n \
               '--update[update subscription]' \
               '--list[list all subscription]' \
               '--switch[switch to node of number]' \
               '--status[show current status]' \
               '--stop[sto current node]' \
               '--test[test all node]'
}

_ssr_cli "$@"
