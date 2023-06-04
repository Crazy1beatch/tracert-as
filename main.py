import argparse

from tracesers.route_tracer import Traceroute


def get_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("target", help="IP-address or DNS name of target")
    parser.add_argument("--ttl", type=int, help="Max hops", default=30)
    return parser


def main():
    parser = get_parser()
    args = parser.parse_args()
    traceroute = Traceroute(args.target, args.ttl)
    trace_result = traceroute.make_trace()
    for i in range(len(trace_result)):
        if trace_result[i] is None:
            print(f"{i + 1}. *")
        else:
            print(f"{i + 1}. {trace_result[i]}")


if __name__ == '__main__':
    main()
