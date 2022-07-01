abstract record fallible<TReturn>;

record error<TReturn> extends fallible<TReturn> {
	readonly array<char> msg;
}

final record success<TReturn> extends fallible<TReturn> {
	readonly TReturn result;
}

proc fallibleFunction(int i) return fallible<int> {
	if(i % 5 == 2)
		return new error<int> {
			msg = "I don't like 5 and 2";
		};
	return success<int> {
		result = 7;
	};
}

auto err = fallibleFunction(52);
if(err is error<any>)
	println(dynamic_cast<error<any>>(err).msg);
else
	println("I am happy!");

abstract record nullable<Ttype>;
	final record null<Ttype> extends nullable<Ttype>
	final record notnull<Ttype> extends nullable<Ttype> {
		Ttype value;
	}

abstract record ipAddr;
	final record ipv4 extends ipAddr {
		int addr;
	}
	final record ivp6 extends ipAddr {
		array<int> data;
	}

proc doSomeIpStuff<addrType extends ipAddr>(addrType addr) {
	if(addrType is ipv4)
		println("Ipv4 stuff....");
	else if(addrType is ipv6) 
		println("Ipv6 stuff.....");
}