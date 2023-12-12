import PKI.demo_pki as demo_pki


def pki_performance_routine(c_init=10):
    return demo_pki.pki_routine(c_init)


if __name__ == "__main__":
    pki_performance_routine()
