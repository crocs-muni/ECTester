import io
import math
import random
import itertools
import warnings

import cypari2
from cysignals.alarm import alarm, AlarmInterrupt

from matplotlib import pyplot as plt
from collections import Counter
from tqdm.auto import tqdm, trange

from pyecsca.misc.cfg import TemporaryConfig
from pyecsca.misc.utils import TaskExecutor
from pyecsca.ec.mod import mod, RandomModAction
from pyecsca.ec.point import Point
from pyecsca.ec.model import ShortWeierstrassModel
from pyecsca.ec.params import load_params_ectester, get_params
from pyecsca.ec.mult import LTRMultiplier, RTLMultiplier, ScalarMultiplicationAction
from pyecsca.ec.context import local, DefaultContext
from pyecsca.ec.countermeasures import GroupScalarRandomization, AdditiveSplitting, MultiplicativeSplitting, EuclideanSplitting, BrumleyTuveri
from utils import *
import cypari2
pari = cypari2.Pari(256_000_000, 2_000_000_000)




class CounterTest:


    def __init__(self):
        model = ShortWeierstrassModel()
        self.coords = model.coordinates["projective"]

        add = self.coords.formulas["add-2007-bl"]
        dbl = self.coords.formulas["dbl-2007-bl"]
        ltr = LTRMultiplier(add, dbl, complete=False)
        self.multiplier = ltr


    def load_all_results(self,card,tag):
        lines = []
        filepath = f"results/{card}/{self.test}"
        if os.path.exists(filepath):
            for file in os.listdir(filepath):
                if tag in file:
                    with open(os.path.join(filepath,file)) as f:
                        lines.extend(f.readlines()[1:])

        if len(lines)==0:
            raise Exception("Not measured or something went wrong\n")
        return [line.strip().split(";") for line in lines]

    def load_csv_signatures(self,card,tag):
        lines = self.load_all_results(card,tag)
        sigs = []
        for line in lines:
            success,error,sig,valid,_,nonce_hex,key_hex,_,curve_csv,_,_,_ = line
            try:
                sigs.append({"success":success, "signature":parse_ecdsa_signature(bytes.fromhex(sig)), "nonce": int(nonce_hex,16), "key":int(key_hex,16), "valid":valid, "curve":curve_csv})
            except ValueError:
                sigs.append({})
        return sigs

    def load_csv_ecdhs(self,card,tag):
        lines = self.load_all_results(card,tag)
        ecdhs = []
        for line in lines:
            success,error,secret,key,_,curve_csv,_,_,_ = line
            try:
                ecdhs.append({"success":success, "secret":int(secret,16), "key":int(key,16), "curve":curve_csv})
            except ValueError:
                ecdhs.append({})
        return ecdhs

    def load_csv_keygens(self,card,tag):
        lines = self.load_all_results(card,tag)
        keygens = []
        for line in lines:
            success,error,key,point,curve_csv,_,_,_ = line
            try:
                keygens.append({"success":success, "key":int(key,16), "point":parse_04point(point), "curve":curve_csv})
            except ValueError:
                keygens.append({})
        return keygens

    def existing_measurements(self,cards, tag):
        print(f"Avaliable measurements for {tag} on:")
        filtered = []
        for card in cards:
            try:
                assert self.load_all_results(card,tag)
                filtered.append(card)
            except:
                continue
        print(", ".join(filtered))
        print()





class Test3n(CounterTest):


    def __init__(self,curve_path,point_path):

        super().__init__()
        self.test = "test3n"
        self.params = load_params_ectester(curve_path, "projective")
        self.point = csv_to_point(point_path, self.params, self.coords)
        self.cofactor = 3
        self.n = self.params.order

        self.multiplier.init(self.params,self.point)
        self.cofactor_point = self.multiplier.multiply(int(self.n))


    def find_mod(self, scalar, compare):
        kP = self.multiplier.multiply(scalar)
        for i in range(self.cofactor):
            if compare(kP):
                return i
            kP = self.multiplier._add(kP,self.cofactor_point)
        return -1

    def print_statistics(self,remainders):
        for krem, rems in remainders.items():
            print(f"k = {krem} mod {self.cofactor}, total = {sum(rems)}")
            for i,count in enumerate(rems[:-1]):
                print(f"k+{i}*n: {count}")
            if rems[-1]:
                print(f"remaining!: {rems[-1]}")
        print()



    def print_ecdh(self,card, tag="ecdh"):

        self.multiplier.init(self.params,self.point)
        remainders = {i:[0]*(self.cofactor+1) for i in range(self.cofactor)}
        for ecdh_result in  self.load_csv_ecdhs(card,tag):
            key, secret = ecdh_result["key"],ecdh_result["secret"]
            compare = lambda point: sha(point.to_affine().x)==secret
            remainders[key%self.cofactor][self.find_mod(key,compare)]+=1
        self.print_statistics(remainders)



    def print_ecdsa(self,card,tag = "ecdsa"):

        self.multiplier.init(self.params,self.params.generator)
        remainders = {i:[0]*(self.cofactor+1) for i in range(self.cofactor)}
        for signature in self.load_csv_signatures(card,tag):
            r,s = signature["signature"]
            nonce = signature["nonce"]
            compare = lambda point: int(point.to_affine().x)%self.n==r%self.n
            remainders[nonce%self.cofactor][self.find_mod(nonce,compare)]+=1
        self.print_statistics(remainders)


    def print_keygen(self,card,tag = "keygen"):

        self.multiplier.init(self.params,self.params.generator)
        remainders = {i:[0]*(self.cofactor+1) for i in range(self.cofactor)}
        for keygen in self.load_csv_keygens(card,tag):
            xy, key = keygen["point"], keygen["key"]
            genpoint = tuple_to_point(xy,self.params,self.coords)
            compare = lambda point: point.to_affine()==genpoint.to_affine()
            remainders[key%self.cofactor][self.find_mod(key,compare)]+=1
        self.print_statistics(remainders)



class Testinverse(CounterTest):

    def __init__(self,curve_path,point_path,cofactor):


        super().__init__()
        self.test = "testinverse"
        self.params = load_params_ectester(curve_path, "projective")
        self.point = csv_to_point(point_path, self.params, self.coords)
        self.cofactor = cofactor
        self.n = self.params.order

    def print_statistics(self,total,correct):
        print(f"Total: {total}")
        print(f"Correct: {correct}")
        print()

    def print_ecdh(self,card, tag = None):
        if not tag: tag = f"ecdh_{self.cofactor}"
        self.multiplier.init(self.params,self.point)
        total,correct = 0,0
        for ecdh_result in self.load_csv_ecdhs(card,tag):
            total+=1
            try:
                secret,key = ecdh_result["secret"], ecdh_result["key"]
                kP = self.multiplier.multiply(key).to_affine()
                correct += (sha(kP.x)==secret)
            except KeyError:
                continue
        self.print_statistics(total,correct)



    def print_ecdsa(self,card, tag = None):
        if not tag: tag = f"ecdsa_{self.cofactor}"
        sigs = self.load_csv_signatures(card,tag)
        total,correct = 0,0
        for sig in sigs:
            total+=1
            try:
                correct += sig["valid"]=="1"
            except KeyError:
                continue
        self.print_statistics(total,correct)


    def print_keygen(self,card, tag = None):
        if not tag: tag = f"keygen_{self.cofactor}"
        self.multiplier.init(self.params,self.params.generator)
        total,correct = 0,0
        for keygen in self.load_csv_keygens(card,f"keygen_{self.cofactor}"):
            total+=1
            try:
                xy, key = keygen["point"], keygen["key"]
                genpoint = tuple_to_point(xy,self.params,self.coords).to_affine()
                kP = self.multiplier.multiply(key).to_affine()
                correct += (kP==genpoint)
            except KeyError:
                continue
        self.print_statistics(total,correct)





class Testk10(CounterTest):

    def __init__(self, curve_path, point_path, k):
        super().__init__()
        self.k = 10
        self.test = "testk10"
        self.params = load_params_ectester(curve_path, "projective")
        self.point = csv_to_point(point_path, self.params, self.coords)
        self.n = self.params.order

        self.multiplier.init(self.params,self.point)
        kP = self.multiplier.multiply(k).to_affine()
        self.correct_secret = sha(kP.x)

    def print_statistics(self,total,correct):
        print(f"Total computed: {total}")
        print(f"Correct: {correct}")
        print()

    def print_ecdh(self, card, tag = "ecdh"):

        total, correct = 0,0
        for ecdh_result in self.load_csv_ecdhs(card, tag):
            total+=1
            if self.correct_secret==ecdh_result["secret"]:
                correct+=1
        self.print_statistics(total,correct)




def divisors(primes, powers):
    for comb in itertools.product(*[range(power+1) for power in powers]):
        value = 1
        for prime, power in zip(primes, comb):
            value *= prime**power
        yield value

def pari_factor(number):
    pari = cypari2.Pari(256_000_000, 2_000_000_000)
    factors = pari.factor(number)
    primes = list(map(int, factors[0]))
    powers = list(map(int, factors[1]))
    return primes, powers

def pari_dlog(e, P, G, real_n, facts_str):
    e[15][0] = real_n
    facts = pari(facts_str)
    dlog = pari.elllog(e, P, G, facts)
    return int(dlog)



class TestEpsilon_GSR(CounterTest):

    def __init__(self, curve_path, point_path, realn_path):

        super().__init__()
        self.test = "testdn"

        self.params = load_params_ectester(curve_path, "projective")
        self.point = csv_to_point(point_path, self.params, self.coords)
        self.n = self.params.order

        with open(realn_path) as f:
            self.real_n = int(f.read(),16)
        self.epsilon = self.n-self.real_n

        self.a = int(self.params.curve.parameters["a"])
        self.b = int(self.params.curve.parameters["b"])
        self.p = int(self.params.curve.prime)
        self.x = int(self.params.generator.X)
        self.y = int(self.params.generator.Y)
        self.pari_real_n_facts = repr(pari.factor(self.real_n))
        self.pari_curve = pari.ellinit([self.a,self.b],self.p)




    def compute_mask(self,scalar,point_candidates,G):
        for P in point_candidates:
            d = pari_dlog(self.pari_curve, [int(P.x),int(P.y)], [int(G.X),int(G.Y)], self.real_n, self.pari_real_n_facts)
            for dp in [d,self.real_n-d]:
                scalar = int(scalar)
                if (dp-scalar)%self.epsilon==0:
                    mask = int((dp-scalar)//self.epsilon)
                    return mask
        raise Exception("No mask found")

    def is_correct_curve(self,result):
        p,a,b,x,y,n,h = map(lambda x: int(x,16), result["curve"].split(","))
        return (p,a,b,x,y,n) == (self.p,self.a,self.b,self.x,self.y,self.n)

    def print_statistics(self,masks):
        for mask in masks:
            print(f"Mask size: {mask.bit_length()}, mask value: {mask}")
        print()

    def lift_x(self,x):
        return self.params.curve.affine_lift_x(mod(x,self.p)).pop()


    def test_masks(self,masks,scalars,point,results,compare):

        for mask,result,scalar in zip(masks,results,scalars):
            masked_key = int(scalar+mask*self.params.order)
            self.multiplier.init(self.params,point,bits= masked_key.bit_length())
            kP = self.multiplier.multiply(masked_key).to_affine()
            assert compare(result,kP)


    def recover_ecdh_plain(self,card, tag = "ecdh", N = 5):
        filtered_results = [res for res in self.load_csv_ecdhs(card,tag) if self.is_correct_curve(res)]
        masks,results,keys = [],[],[]
        for ecdh_result in filtered_results[:N]:
            key, secret = ecdh_result["key"],ecdh_result["secret"]
            R = self.lift_x(secret)
            masks.append(self.compute_mask(key,[R],self.point))
            results.append(R)
            keys.append(key)

        compare = lambda p,q: p.x==q.x
        self.test_masks(masks,keys,self.point,results,compare)
        self.print_statistics(masks)


    def recover_ecdsa(self,card, tag = "ecdsa", N = 5):

        filtered_results = [res for res in self.load_csv_signatures(card,tag) if self.is_correct_curve(res)]
        masks,results,nonces = [],[],[]
        for line in filtered_results[:N]:
            nonce = line["nonce"]
            r, s = line["signature"]
            r = r%self.n
            candidates = [self.lift_x(r)]+[self.lift_x(r+i*self.n) for i in range(1,(self.p-r)//self.n)]
            mask = self.compute_mask(nonce,candidates,self.params.generator)
            masks.append(mask)
            nonces.append(nonce)
            results.append(r)

        compare = lambda r,q: r%self.n==int(q.x)%self.n
        self.test_masks(masks,nonces,self.params.generator,results,compare)
        self.print_statistics(masks)



    def recover_keygen(self,card,tag="keygen", N=5):
        filtered_results = [res for res in self.load_csv_keygens(card,tag) if self.is_correct_curve(res)]
        masks,results,keys = [],[],[]
        for keygen_result in filtered_results[:N]:
            key, xy = keygen_result["key"],keygen_result["point"]
            R = tuple_to_point(xy,self.params,self.coords).to_affine()
            masks.append(self.compute_mask(key,[R],self.params.generator))
            keys.append(key)
            results.append(R)
        compare = lambda p,q: p==q
        self.test_masks(masks,keys,self.params.generator,results,compare)
        self.print_statistics(masks)



class TestEpsilon_Multiplicative(CounterTest):

    def __init__(self, curve_path, point_path, realn_path):

        super().__init__()
        self.test = "testdn"

        self.params = load_params_ectester(curve_path, "projective")
        self.point = csv_to_point(point_path, self.params, self.coords)
        self.n = self.params.order

        with open(realn_path) as f:
            self.real_n = int(f.read(),16)
        self.epsilon = self.n-self.real_n

        self.a = int(self.params.curve.parameters["a"])
        self.b = int(self.params.curve.parameters["b"])
        self.p = int(self.params.curve.prime)
        self.x = int(self.params.generator.X)
        self.y = int(self.params.generator.Y)
        self.pari_real_n_facts = repr(pari.factor(self.real_n))
        self.pari_curve = pari.ellinit([self.a,self.b],self.p)

        #
        self.candidates = None


    def compute_t(self,scalar,point_candidates,G):
        for P in point_candidates:
            d = pari_dlog(self.pari_curve, [int(P.x),int(P.y)], [int(G.X),int(G.Y)], self.real_n, self.pari_real_n_facts)
            for dp in [d,self.real_n-d]:
                scalar = int(scalar)
                if (dp-scalar)%self.epsilon==0:
                    mask = int((dp-scalar)//self.epsilon)
                    return mask
        raise Exception("No mask found")

    def is_correct_curve(self,result):
        p,a,b,x,y,n,h = map(lambda x: int(x,16), result["curve"].split(","))
        return (p,a,b,x,y,n) == (self.p,self.a,self.b,self.x,self.y,self.n)

    def print_statistics(self,masks):
        for mask in masks:
            print(f"Mask size: {mask.bit_length()}, mask value: {mask}")
        print()

    def compute_candidates(self,lower_bound, upper_bound):
        all_divisors = [list(divisors(*pari_factor(k+t*self.n))) for t,k in self.ts]
        filtered = []
        for divs in all_divisors:
            filtered.append([d for d in divs if lower_bound<=d.bit_length()<=upper_bound])
            print(f"Found {len(filtered[-1])} candidates")
        self.candidates = filtered

    def plot_divisor_histogram(self,candidates):
        candidate_bits = [c.bit_length() for c in candidates]
        max_amount = max(candidate_amounts)
        fig = plt.subplots()
        plt.hist(candidate_amounts, range=(1, max_amount), align="left", density=True, bins=range(1, max_amount))
        plt.xlabel("number of candidate masks")
        plt.ylabel("proportion")
        plt.xticks(range(max_amount))
        plt.xlim(0, 20);
        plt.show()

    def lift_x(self,x):
        return self.params.curve.affine_lift_x(mod(x,self.p)).pop()


    def test_ts(self,ts,scalars,point,results,compare):

        for t,result,scalar in zip(ts,results,scalars):
            masked_key = int(scalar+t*self.params.order)
            self.multiplier.init(self.params,point,bits= masked_key.bit_length())
            kP = self.multiplier.multiply(masked_key).to_affine()
            assert compare(result,kP)


    def recover_ecdh_plain_size(self,card, tag = "ecdh", N = 5):
        filtered_results = [res for res in self.load_csv_ecdhs(card,tag) if self.is_correct_curve(res)]
        ts,results,keys = [],[],[]
        for ecdh_result in filtered_results[:N]:
            key, secret = ecdh_result["key"],ecdh_result["secret"]
            R = self.lift_x(secret)
            ts.append(self.compute_t(key,[R],self.point))
            results.append(R)
            keys.append(key)

        compare = lambda p,q: p.x==q.x
        self.test_ts(ts,keys,self.point,results,compare)
        self.ts = zip(ts,keys)
        print(set(t.bit_length() for t in ts))


    def recover_ecdsa_size(self,card, tag = "ecdsa", N = 5):

        filtered_results = [res for res in self.load_csv_signatures(card,tag) if self.is_correct_curve(res)]
        ts,results,nonces = [],[],[]
        for line in filtered_results[:N]:
            nonce = line["nonce"]
            r, s = line["signature"]
            r = r%self.n
            candidates = [self.lift_x(r)]+[self.lift_x(r+i*self.n) for i in range(1,(self.p-r)//self.n)]
            print(nonce,self.p,r,self.n,candidates)
            t = self.compute_t(nonce,candidates,self.params.generator)
            ts.append(t)
            nonces.append(nonce)
            results.append(r)

        compare = lambda r,q: r%self.n==int(q.x)%self.n
        self.test_ts(ts,nonces,self.params.generator,results,compare)
        self.ts = zip(ts,nonces)
        print(set(t.bit_length() for t in ts))


    def recover_keygen_size(self,card,tag="keygen", N=5):
        filtered_results = [res for res in self.load_csv_keygens(card,tag) if self.is_correct_curve(res)]
        ts,results,keys = [],[],[]
        for keygen_result in filtered_results[:N]:
            key, xy = keygen_result["key"],keygen_result["point"]
            R = tuple_to_point(xy,self.params,self.coords).to_affine()
            masks.append(self.compute_t(key,[R],self.params.generator))
            ts.append(key)
            results.append(R)
        compare = lambda p,q: p==q
        self.test_ts(ts,keys,self.params.generator,results,compare)
        self.ts = zip(ts,keys)
        print(set(t.bit_length() for t in ts))
