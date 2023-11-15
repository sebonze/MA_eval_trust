from prettytable import PrettyTable


def create_table(solution, crypto_info, min_time, max_time, mean_time, num_routines):
    # Initialize table
    table = PrettyTable()

    # Add columns
    table.field_names = ["Trust Solution", "Crypto", "Min Time", "Max Time", "Mean Time", "Number of Routines"]

    # Add row with the provided data
    table.add_row([solution, crypto_info, min_time, max_time, mean_time, num_routines])

    # Print table
    print(table)


if __name__ == "__main__":
    create_table("Blockchain", "RSA", 1, 3, 2,100)
    create_table("Blockchain", "RSA", 1, 3, 2, 100)