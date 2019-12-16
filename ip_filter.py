import iptc
import sys

rule = iptc.Rule()
rule.in_interface = "eth0"
rule.src = sys.argv[1]
rule.protocol = "tcp"
target = iptc.Target(rule, "DROP")
rule.target = target

chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT)
chain.insert_rule(rule)