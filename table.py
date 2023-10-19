from prettytable import PrettyTable


def create_table(file_size, num_cycles, needed_time, num_messages):
    # Initialize table
    table = PrettyTable()

    # Add columns
    table.field_names = ["File Size", "Processing Cycles", "Needed Time", "Number of Messages"]

    # Add row with the provided data
    table.add_row([file_size, num_cycles, needed_time, num_messages])

    # Print table
    print(table)


if __name__ == "__main__":
    create_table("500MB", 20, "2s", 100)