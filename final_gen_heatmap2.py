import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

def generate_contingency_table(file_path, top_cwes):
    # Load the data
    data = pd.read_excel(file_path)

    # Splitting FinalCWE entries with multiple CWE IDs
    data_expanded = data.assign(FinalCWE=data['FinalCWE'].str.split(',')).explode('FinalCWE').reset_index(drop=True)
    data_expanded['FinalCWE'] = data_expanded['FinalCWE'].str.strip()

    # Determine the top ten vendors
    top_vendors = data_expanded['vendorProject'].value_counts().head(10).index.tolist()
    data_top_vendors = data_expanded[data_expanded['vendorProject'].isin(top_vendors)]

    # Count CWE occurrences for each vendor and filter for top CWEs
    cwe_counts = data_expanded['FinalCWE'].value_counts().head(10).index.tolist()
    data_top_cwes = data_top_vendors[data_top_vendors['FinalCWE'].isin(cwe_counts)]

    # Count the occurrences of the top CWEs for the top vendors
    cwe_counts_per_vendor = data_top_cwes.groupby(['vendorProject', 'FinalCWE']).size().reset_index(name='count')

    # Create a contingency table for the top CWEs and vendors
    contingency_table = cwe_counts_per_vendor.pivot(index='vendorProject', columns='FinalCWE', values='count').fillna(0)

    return contingency_table

def save_table_as_png(table, file_name):
    # Plotting the table using seaborn
    plt.figure(figsize=(12, 8))
    sns.heatmap(table, annot=True, cmap="YlGnBu", fmt="g", cbar_kws={'label': 'Count'})
    plt.title("Contingency Table of Top CWEs for Top Vendors")
    plt.ylabel("Vendor")
    plt.xlabel("CWE")

    # Saving the plot as a PNG file
    plt.savefig(file_name, bbox_inches='tight')
    plt.close()

# Path to your Excel file
file_path = '/home/Addy/working-folder/AIT_664/data_set/FINAL_LIMITED_known_exploited_vulnerabilities_lugo_edited.xlsx'

# Top ten CWEs based on overall frequency in the dataset
top_cwes = [
    "CWE-269", "CWE-20", "CWE-119", "CWE-787", "CWE-94",
    "CWE-78", "CWE-416", "CWE-22", "CWE-77", "CWE-287"
]

# Generate the contingency table for the top ten CWEs
contingency_table = generate_contingency_table(file_path, top_cwes)

# Save the table as a PNG file
png_file_name = '/home/Addy/working-folder/AIT_664/images/F2_contingency_table.png'
save_table_as_png(contingency_table, png_file_name)
