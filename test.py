import iptc

def print_iptables_rules():
    table = iptc.Table(iptc.Table.FILTER)
    table.refresh()
    for chain in table.chains:
        print("=======================")
        print("Chain:", chain.name)
        for rule in chain.rules:
            print("Rule: proto:", rule.protocol, "src:", rule.src, "dst:", rule.dst, 
                  "in:", rule.in_interface, "out:", rule.out_interface)
            print("Matches:", end=" ")
            for match in rule.matches:
                print(match.name, end=" ")
            print("Target:", rule.target.name)
    print("=======================")

if __name__ == "__main__":
    print_iptables_rules()
