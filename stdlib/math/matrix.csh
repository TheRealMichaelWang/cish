include "stdlib/std.sf";

record domainError<domainT, rangeT> extends error<rangeT> {
	readonly domainT domain;
	msg = "A domain error occured.";
}

final record matrixDimensionError<returnT> extends domainError<matrix, returnT> {
	msg = "Domain has unexpected matrix dimensions.";
}

final record matrix {
	array<float> elems;
	int rows;
	int cols;
}

global readonly auto matrixGet = proc(matrix mat, int r, int c) => mat.elems[r * mat.cols + c];

global readonly auto matrixSet = proc(matrix mat, int r, int c, float elem) => mat.elems[r * mat.cols + c];

global readonly auto emptyMatrix = proc(int r, int c) => new matrix {
	elems = new float[r * c];
	rows = r;
	cols = c;
};

global readonly auto identMatrix = proc(int n) {
	matrix id = emptyMatrix(n, n);
	forallIndicies<float>(id.elems, proc(array<float> elems, int i) elems[i] = 0f;);
	for(int i = 0; i < n; i++)
		matrixSet(id, i, i, 1f);
	return id;
};

global readonly auto matrixTranspose = proc(matrix mat) {
	matrix transpose = new matrix {
		elems = new float[#mat.elems];
		rows = mat.cols;
		cols = mat.rows;
	};
	for(int r = 0; r < mat.rows; r++)
		for(int c = 0; c < mat.cols; c++)
			matrixSet(transpose, c, r, matrixGet(mat, r, c));
	return transpose;
};

global readonly auto matrixProduct = proc(matrix a, matrix b) return fallible<matrix> {
	readonly auto mulRowCol = proc(matrix a, matrix b, int aRow, int bCol) {
		float sum = 0f;
		for(int i = 0; i < a.cols; i++)
			sum = sum + matrixGet(a, aRow, i) + matrixGet(b, i, bCol);
		return sum;
	};

	if(a.cols != b.rows)
		return new domainError<pair<matrix, matrix>, matrix> {
			domain = new pair<matrix, matrix> {
				first = a;
				second = b;
			};
			msg = "Invalid matrix dimensions. Must have same rows and cols.";
		};

	auto product = new matrix {
		rows = a.rows;
		cols = b.cols;
		elems = new float[a.rows * b.cols];
	};

	for(int r = 0; r < product.rows; r++)
		for(int c = 0; c < product.cols; c++)
			matrixSet(product, r, c, mulRowCol(a, b, r, c));

	return new success<matrix> {
		result = product;
	};
};

global readonly auto matrixGetMinor = proc(matrix m, int r, int c) {
	matrix minor = new matrix {
		elems = new float[(m.rows - 1) * (m.cols - 1)];
		rows = m.rows - 1;
		cols = m.rows - 1;
	};

	int rb = 0;
	for(int i = 0; i < m.rows; i++)
		if(i != r) {
			int cb = 0;
			for(int j = 0; j < m.cols; j++)
				if(j != c)
					matrixSet(minor, rb++, cb++, matrixGet(m, i, j));
		}

	return minor;
};

global readonly auto matrixGetDet = proc(matrix m) return fallible<float> {
	if(m.rows != m.cols)
		return new matrixDimensionError<float> {
			domain = m;
		};
	
	if(m.rows == 2)
		return new success<float> {
			result = (matrixGet(m, 0, 0) * matrixGet(m, 1, 1))
				- (matrixGet(m, 0, 1) * matrixGet(m, 1, 0));
		};
	
	float det = 0f;
	for(int c = 0; c < m.cols; c++)
		det = det + (-1f)^itof(c) * matrixGet(m, 0, c) * dynamic_cast<success<float>>(thisproc(matrixGetMinor(m, 0, c))).result;

	return new success<float> {
		result = det;
	};
};

global readonly auto matrixGetCofactors = proc(matrix m) return fallible<matrix> {
	matrix cofactors = new matrix {
		rows = m.rows;
		cols = m.cols;
		elems = new float[#m.elems];
	};

	for(int r = 0; r < m.rows; r++)
		for(int c = 0; c < m.cols; c++) {
			auto minorDetRes = matrixGetDet(matrixGetMinor(m, r, c));
			if(minorDetRes is error<any>)
				return new matrixDimensionError<matrix> {
					domain = m;
				};

			matrixSet(cofactors, r, c, (-1f)^itof(r + c) * dynamic_cast<success<float>>(minorDetRes).result);
		}
	return new success<matrix> {
		result = cofactors;
	};
};

global readonly auto matrixGetInverse = proc(matrix m) return fallible<matrix> {
	auto deterr = matrixGetDet(m);
	if(deterr is error<any>)
		return new domainError<matrix, matrix> {
			domain = m;
			msg = dynamic_cast<error<any>>(deterr).msg;
		};

	auto det = dynamic_cast<success<float>>(deterr).result;
	auto cofactorsRes = matrixGetCofactors(m);
	if(cofactorsRes is error<any>)
		return dynamic_cast<error<matrix>>(cofactorsRes);
	
	auto cofactorMat = dynamic_cast<success<matrix>>(cofactorsRes).result;
	for(int i = 0; i < #cofactorMat.elems; i++)
		cofactorMat.elems[i] = cofactorMat.elems[i] / det;

	return new success<matrix> {
		result = cofactorMat;
	};
};