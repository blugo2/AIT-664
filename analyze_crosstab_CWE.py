import pandas as pd

# Modify pandas' default display options to show all rows
pd.set_option('display.max_rows', None)
pd.set_option('display.max_columns', 3) 
pd.set_option('display.width', None)
pd.set_option('display.max_colwidth', None)

def load_data(file_path):
    # Load the dataset
    data = pd.read_excel(file_path)
    return data

def preprocess_data(data):
    # Splitting the CWEs into a list where multiple CWEs are combined
    data['CWE_List'] = data['FinalCWE'].astype(str).apply(lambda x: x.split(', '))
    # Exploding the dataframe so each CWE gets its own row
    exploded_data = data.explode('CWE_List')
    return exploded_data

def get_top_cwes(exploded_data):
    # Calculating the frequency of top ten each CWE
    cwe_counts = exploded_data['CWE_List'].value_counts()

    return cwe_counts.head(10)
#    return cwe_counts

def get_top_venders(exploded_data):
    # Calculating the frequency of top tean venders
    vender_counts = exploded_data['vendorProject'].value_counts()

    return vender_counts.head(10)
#    return vender_counts


def get_vendor_product_association(exploded_data):
    # Creating a DataFrame that relates CWEs with vendors and products
    vendor_cwe = exploded_data.groupby(['vendorProject', 'CWE_List']).size().reset_index(name='Count')
    product_cwe = exploded_data.groupby(['product', 'CWE_List']).size().reset_index(name='Count')

    # Finding the top vendors and products associated with the most common CWEs
    top_vendors_cwe = vendor_cwe.sort_values(by='Count', ascending=False).head(10)
    top_products_cwe = product_cwe.sort_values(by='Count', ascending=False).head(10)

    return top_vendors_cwe, top_products_cwe

def main(file_path):
    data = load_data(file_path)
    exploded_data = preprocess_data(data)

    # Get the top CWEs
    top_cwes = get_top_cwes(exploded_data)
    print("Top CWEs:")
    print(top_cwes)

    # Get the top Venders
    top_venders = get_top_venders(exploded_data)
    print("\nTop Venders:")
    print(top_venders)

    # Get the top vendor and product associations with CWEs
    top_vendors, top_products = get_vendor_product_association(exploded_data)
    print("\nTop Vendors Associated with CWEs:")
    print(top_vendors)

    print("\nTop Products Associated with CWEs:")
    print(top_products)

# Path to dataset file
file_path = '/home/Addy/working-folder/AIT_664/data_set/TEST_known_exploited_vulnerabilities_lugo_edited.xlsx'
main(file_path)

