include "stdlib/data/list.csh";

abstract record animal {
	readonly array<char> name;
}
	final record dog extends animal;
	final record cat extends animal;

list<dog> dogs = new list<dog>;
listAdd<dog>(dogs, new dog { name = "fibbo"; });
listAdd<dog>(dogs, new dog { name = "spot"; });
listAdd<dog>(dogs, new dog { name = "dick"; });

list<animal> animals = dogs; $downcast should be succesful

listAdd<animal>(animals, new cat { name = "fluffy"; }); $should invoke type guard