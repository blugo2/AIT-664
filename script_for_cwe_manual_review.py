import pandas as pd

# Modify pandas' default display options to show all rows
pd.set_option('display.max_rows', None)
pd.set_option('display.max_columns', 3) #excludes the shortDescription column, too large to be readable in terminal
pd.set_option('display.width', None) 
pd.set_option('display.max_colwidth', None)

def assign_cwe(row):
    vulnerability_name = row['vulnerabilityName']
    shortDescription = row['shortDescription']
    
    if "Privilege Escalation" in vulnerability_name or "Privilege Escalation" in shortDescription:
        return "CWE-269"
    elif ("Remote Code Execution" in vulnerability_name or "Code Execution" in vulnerability_name or
          "Remote Code Execution" in shortDescription or "Code Execution" in shortDescription):
        return "CWE-20/CWE-94"
    elif "Denial-of-Service" in vulnerability_name or "Denial-of-Service" in shortDescription:
        return "CWE-400"
    elif "Information Disclosure" in vulnerability_name or "Information Disclosure" in shortDescription:
        return "CWE-200"
    elif "Security Feature Bypass" in vulnerability_name or "Security Feature Bypass" in shortDescription:
        return "CWE-285"
    elif "Memory Corruption" in vulnerability_name or "Memory Corruption" in shortDescription:
        return "CWE-119"
    elif "Buffer Overflow" in vulnerability_name or "Buffer Overflow" in shortDescription:
        return "CWE-120"
    elif "Use-After-Free" in vulnerability_name or "Use-After-Free" in shortDescription:
        return "CWE-416"
    elif "Sandbox Bypass" in vulnerability_name or "Sandbox Bypass" in shortDescription:
        return "CWE-912"
    else:
        return "Requires Manual Review"

df = pd.read_csv("/home/Addy/working-folder/AIT_664/data_set/known_exploited_vulnerabilities_lugo_edited.csv")
none_cwe_rows = df[df['CWE'] == "none"].copy()  # Making a copy to avoid SettingWithCopyWarning
none_cwe_rows['Assigned CWE'] = none_cwe_rows.apply(assign_cwe, axis=1)
# Print rows requiring manual review
manual_review_rows = none_cwe_rows[none_cwe_rows['Assigned CWE'] == "Requires Manual Review"]
print("Rows requiring manual review:")
print(manual_review_rows[['cveID', 'vulnerabilityName', 'shortDescription', 'Assigned CWE']])
print("\n")  # Add a newline for better separation

# Print rows with assigned CWE IDs
assigned_cwe_rows = none_cwe_rows[none_cwe_rows['Assigned CWE'] != "Requires Manual Review"]
print("Rows with assigned CWE IDs:")
print(assigned_cwe_rows[['cveID', 'vulnerabilityName', 'shortDescription', 'Assigned CWE']])

