import pandas
def getNyuIPandPorts():
    data = pandas.read_excel('logNyuDorm0-300.xlsx')
    result = [tuple(x) for x in data.values]  
    print(len(result))
    print(result)

getNyuIPandPorts()