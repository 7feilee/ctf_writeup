n = 6
R.<a,b,c> = QQ[]
cubic = a*(a+b)*(a+c)+b*(a+b)*(b+c)+c*(b+c)*(c+a) - n*(a+b)*(a+c)*(b+c)
O = [1,-1,0]
E = EllipticCurve_from_cubic(cubic,O,morphism = False)
f = EllipticCurve_from_cubic(cubic,O,morphism = True)
finv = f.inverse()
P = E.gens()[0]
for k in range(1,100):
    Q = finv(k*P)
    if Q[0]>0 and Q[1]>0:
        a,b,c = Q[0],Q[1],Q[2]
        a_r, a_i = a.as_integer_ratio()
        b_r, b_i = b.as_integer_ratio()
        comm = lcm(a_i,b_i)
        a_out,b_out,c_out = a*comm,b*comm,comm
        assert a_out/(b_out+c_out) + b_out/(a_out+c_out) + c_out/(a_out+b_out) == n
        break