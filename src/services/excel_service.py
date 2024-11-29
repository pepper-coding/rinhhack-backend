import pandas as pd

def generate_excel_file():
    data = {"Name": ["Alice", "Bob", "Charlie"], "Age": [25, 30, 35]}
    df = pd.DataFrame(data)
    file_path = "data.xlsx"
    df.to_excel(file_path, index=False)
    return file_path
