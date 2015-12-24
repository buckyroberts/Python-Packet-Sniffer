def print_foods(x):
    return x + 'mmmmmm'

food = ['corn', 'beef', 'ham']

new_foods = map(print_foods, food)

for item in new_foods:
    print(item)


print('hey {} jones'.format('bucky'))
