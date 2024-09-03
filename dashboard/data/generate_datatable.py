"""generate_datatable.py"""

import re
import sys
import subprocess
from pathlib import Path
from datetime import datetime, timedelta
import pandas as pd

LOGS = "/var/log/fwd/db/"
PREFIX = "fwddmp.log.tmp"

# Get/set current dates
today = datetime.now().strftime("_%m_%d_")
old = (datetime.now() - timedelta(days=10)).strftime("%Y/%m/%d %H:%M:%S")

# Define file paths
log_path = Path(LOGS)
data_path = Path(__file__).resolve().parent

# Define the columns based on the structure of the log
columns = [
    "Date/Time", "Source IP Address", "Destination IP Address",
    "Event Description", "Priority"
]

# Set column dtypes
dtypes = {
    "ID": str,
    "Priority": int,
    "Type": str,
    "Event Description": str,
    "Date/Time": str,
    "Protocol": str,
    "Source IP Address": str,
    "Source Port": int,
    "Source URL": str,
    "Source MAC Address": str,
    "Internal Source": str,
    "Blocked Source": bool,
    "Destination IP Address": str,
    "Destination Port": int,
    "Destination URL": str,
    "Destination MAC Address": str,
    "Internal Destination": int,
    "Blocked Destination": int,
    "Good Host": int,
    "Bad Host": int
}


def get_logs() -> list[Path]:
    """Gather filename paths to be processed.

    Returns:
        List of filename paths.
    """

    # Find fles with defined prefix
    matching_files = [
        file for file in log_path.glob(f"{PREFIX}*") if file.is_file()
    ]

    # Get current files to process
    files_to_process = []
    for file in matching_files:
        if today in file.name:
            files_to_process.append(file)
    return files_to_process


def clean_logs(files: list[Path]) -> list[Path]:
    """Copy data do application data directory and strip csv
    files of any lines that do not contain 20 columns of data,
    as those lines are incomplete writes.

    Args:
        files (list[Path]): List of filename paths to be processed.

    Returns:
        List of copied and cleaned filename paths.
    """

    # Remove any lines from log files that are missing data columns
    #  and copy them to are dashboard data directory
    new_files = []
    for file in files:
        new_file = data_path / file.name
        command = f"awk -F, 'NF == 20' {str(file)} > {str(new_file)}"
        process = subprocess.run(command, shell=True, check=True, text=True)
        if process.returncode != 0:
            print("Error occurred during filtering.")
            sys.exit(1)
        new_files.append(new_file)
    return new_files


def clean_csv(in_file: Path, out_file: Path) -> None:
    """Remove duplicates, sort by Date/Time decending, save to a new
    csv file, and delete original csv file.

    Args:
        in_file (Path): Csv filename path to process.
        out_file (Path): Csv filename path of output file.

    Returns:
        None
    """
    # Read the dirty file into a DataFrame
    try:
        df = pd.read_csv(in_file,
                         header=None,
                         encoding="utf-8",
                         names=columns,
                         dtype=dtypes)
    except FileNotFoundError:
        sys.exit(0)

    # Delete dirty file
    in_file.unlink(missing_ok=True)

    # Remove duplicates
    df_dropped = df.drop_duplicates()
    del df

    # Sort by Date/Time
    df_sorted = df_dropped.sort_values(by='Date/Time', ascending=False)
    del df_dropped

    # Write new clean file
    out_file.unlink(missing_ok=True)
    df_sorted.to_csv(out_file, index=False, header=False, encoding="utf-8")


def purge_old_and_update(in_file: Path, out_file: Path) -> None:
    """Purge old events and update with new.

    Args:
        in_file (Path): Csv filename path of new data.
        out_file (Path): Csv filename path to purge/update.

    Returns:
        None
    """
    new_temp_file = Path(data_path / "new_temp.csv")

    # Read existing csv file into a DataFrame
    if out_file.is_file():
        df = pd.read_csv(out_file,
                         header=None,
                         names=columns,
                         chunksize=50000,
                         encoding="utf-8",
                         dtype=dtypes,
                         on_bad_lines="skip")

        # Process in 50,000 line chunks
        # Purge old events
        for chunk in df:
            df_purged = chunk[chunk["Date/Time"] > old]
            del chunk
            df_purged.to_csv(new_temp_file,
                             mode="a",
                             index=False,
                             header=False,
                             encoding="utf-8")
            del df_purged
        out_file.unlink()
        new_temp_file.rename(out_file)

    # Read new data csv file into a DateFrame
    try:
        df_final = pd.read_csv(in_file,
                               header=None,
                               names=columns,
                               encoding="utf-8",
                               dtype=dtypes,
                               on_bad_lines="skip")
    except FileNotFoundError:
        sys.exit(0)

    # Append new data to existing csv event data file
    if not df_final.empty:
        df_final.to_csv(out_file,
                        mode="a",
                        index=False,
                        header=False,
                        encoding="utf-8")
    del df_final

    # Delete temp temp file
    in_file.unlink(missing_ok=True)


def main() -> None:
    """Do the stuff."""
    logs = get_logs()
    files = clean_logs(logs)
    out_file = Path(data_path / "events.csv")
    temp_file = Path(data_path / "temp.csv")

    # Define the columns based on the structure of the log
    raw_columns = [
        "ID", "Priority", "Type", "Event Description", "Date/Time", "Protocol",
        "Source IP Address", "Source Port", "Source URL", "Source MAC Address",
        "Internal Source", "Blocked Source", "Destination IP Address",
        "Destination Port", "Destination URL", "Destination MAC Address",
        "Internal Destination", "Blocked Destination", "Bad Host", "Good Host"
    ]

    # Process each log file
    for file in files:

        # Read the log file into a DataFrame
        df = pd.read_csv(file,
                         header=None,
                         names=raw_columns,
                         chunksize=50000,
                         encoding="utf-8",
                         dtype=dtypes,
                         on_bad_lines="skip")

        # Process in 50,000 line chunks
        for chunk in df:

            # Remove unblocked events
            df_blocked = chunk[chunk["Blocked Source"]]
            del chunk

            # Remove unnecessary columns
            df_columns = df_blocked[columns]
            del df_blocked

            # Clean the "Description" column
            df_columns["Event Description"] = df_columns[
                "Event Description"].apply(
                    lambda desc: re.sub(r"^\[.*?\>\s*", "", desc))

            # Drop duplicate lines
            df_dropped = df_columns.drop_duplicates()
            del df_columns

            # Write the processed DataFrame to a CSV file
            df_dropped.to_csv(temp_file,
                              mode="a",
                              index=False,
                              header=False,
                              encoding="utf-8")
            del df_dropped
            clean_csv(temp_file, temp_file)

        # Delete copied log files
        file.unlink(missing_ok=True)
        print(f"Finished: {file}")

    # Make updated csv file for the dashboard application
    purge_old_and_update(temp_file, out_file)


if __name__ == "__main__":
    main()
