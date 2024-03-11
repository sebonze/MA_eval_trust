import PKI.demo_pki as demo_pki


def pki_performance_routine(c_init=1):
    return demo_pki.run_pki_protocol_sha384(c_init)


if __name__ == "__main__":
    pki_performance_routine()
