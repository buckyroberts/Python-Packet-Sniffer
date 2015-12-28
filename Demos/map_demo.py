income = [10, 30, 75]


def double_money(dollars):
    return dollars * 2

# map takes a iterable and runs it through a function
new_income = list(map(double_money, income))
print(new_income)
