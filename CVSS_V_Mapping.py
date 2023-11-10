
import re

def map_cvssv2_to_cvssv3_qualitative(cvssv2_score):
    """
    Map a CVSSv2 base score to a CVSSv3.1 qualitative severity rating.
    
    Args:
    - cvssv2_score (float): The CVSSv2 base score.
    
    Returns:
    - str: The CVSSv3.1 qualitative severity rating.
    """
    if cvssv2_score < 0.1:
        return "None"
    elif 0.1 <= cvssv2_score <= 3.9:
        return "Low"
    elif 4.0 <= cvssv2_score <= 6.9:
        return "Medium"
    elif 7.0 <= cvssv2_score <= 10.0:
        return "High (7.0 - 8.9 in CVSSv3.1)" if cvssv2_score <= 8.9 else "Critical (9.0 - 10.0 in CVSSv3.1)"
    else:
        return "Invalid CVSSv2 Score"

def categorize_cvssv3_score(cvssv3_score):
    """
    Categorize a CVSSv3.1 score into its corresponding qualitative severity rating.
    
    Args:
    - cvssv3_score (float): The CVSSv3.1 score.
    
    Returns:
    - str: The CVSSv3.1 qualitative severity rating.
    """
    if cvssv3_score < 0.1:
        return "None"
    elif 0.1 <= cvssv3_score <= 3.9:
        return "Low"
    elif 4.0 <= cvssv3_score <= 6.9:
        return "Medium"
    elif 7.0 <= cvssv3_score <= 8.9:
        return "High"
    elif 9.0 <= cvssv3_score <= 10.0:
        return "Critical"
    else:
        return "Invalid CVSSv3.1 Score"

if __name__ == "__main__":
    try:
        with open("CVE_Nums.txt", "r") as file:
            lines = file.readlines()
            for line in lines:
                line = line.strip()
                # Ensure that the line contains a valid CVSSv2 score
                #if re.match(r"^\d+(\.\d+)?$", line):
                cvssv2_score = float(line)
                #cvssv3_qualitative_rating = map_cvssv2_to_cvssv3_qualitative(cvssv2_score)
                categorize_cvssv3_score = map_cvssv2_to_cvssv3_qualitative(cvssv2_score)
                #print(categorize_cvssv3_score,'')
                match = re.search(r"\d+(\.\d+)?", categorize_cvssv3_score)
                #if match:
                #print(match,'match')
                #converted_score = float(match)
                #print(f"CVSSv2 Score: {cvssv2_score} -> CVSSv3.1 Score: {converted_score} (Severity: {categorize_cvssv3_score(converted_score)})")
                print(f"CVSSv2 Score: {cvssv2_score} -> (CVSSv3.1 Severity: {categorize_cvssv3_score})")
                #else:
                    #print(f"CVSSv2 Score: {cvssv2_score} -> CVSSv3.1 Qualitative Severity Rating: {cvssv3_qualitative_rating}")
                    #print("ERROR")
                #else:
                #    print(f"Ignoring invalid line: {line}")
    except FileNotFoundError:
        print("File CVE_Nums.txt not found!")
    except ValueError:
        print("Invalid value encountered in file. Please ensure all lines contain valid CVSSv2 scores.")

