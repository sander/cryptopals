(ns 'set-1)

(defn bytes->base64 [a]
  (.encodeToString (java.util.Base64/getEncoder) a))

(defn hex->bytes [s]
  (->> s
    (partition 2)
    (map (fn [[c1 c2]]
           (+ (bit-shift-left (Character/digit c1 16) 4)
             (Character/digit c2 16))))
    byte-array))

(defn hex->base64 [s]
  (-> s hex->bytes bytes->base64))

(comment
  ; https://www.cryptopals.com/sets/1/challenges/1
  (= (hex->base64 "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
    "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"))

(defn xor [a1 a2]
  (when (= (count a1) (count a2))
    (byte-array (map bit-xor a1 a2))))

(comment
  ; https://www.cryptopals.com/sets/1/challenges/2
  (= (bytes->base64
       (xor
         (hex->bytes "1c0111001f010100061a024b53535009181c")
         (hex->bytes "686974207468652062756c6c277320657965")))
    (hex->base64 "746865206b696420646f6e277420706c6179")))

(defn single-byte-xor [b a]
  (byte-array (map (fn [b2] (bit-xor b b2)) a)))

(defn bytes->hex [a]
  (let [hex [\0 \1 \2 \3 \4 \5 \6 \7 \8 \9 \a \b \c \d \e \f]]
    (apply str
      (mapcat (fn [b]
                (let [v (bit-and b 0xff)]
                  [(hex (bit-shift-right v 4))
                   (hex (bit-and v 0x0f))]))
        a))))

(def scores
  (into {} (merge
             (map (fn [i]
                    [(unchecked-char i) 1])
               (range (int \A) (+ 0 (int \z))))
             {\a 5 \e 5 \o 5 (char 32) 20 \' 2})))

(defn score [a]
  (->> a (map #(or (scores (unchecked-char %)) 0)) (reduce +)))

(defn break-single-byte-xor-cipher [a]
  (->> (range 256)
      (map unchecked-byte)
      (map (fn [b] [b (single-byte-xor b a)]))
      (map (fn [[b a]] [b (score a) a]))
      (sort-by (fn [[_ s _]] s))
      reverse
      (map (fn [[b s a]] {:cipher b :score s :plaintext (String. a)}))
      (take 3)))

(comment
  ; https://www.cryptopals.com/sets/1/challenges/3
  (let [a (hex->bytes "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")]
    (= (:plaintext (first (break-single-byte-xor-cipher a)))
      "Cooking MC's like a pound of bacon")))
