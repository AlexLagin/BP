import tkinter as tk
import random


### FUNKCIE PRE LOGIKU PROGRAMU ###

def show_frame(frame, clear_inputs=None):
    """Zobrazí daný rám a vymaže vstupné polia, ak sú zadané."""
    if clear_inputs:
        for entry in clear_inputs:
            if isinstance(entry, tk.Entry):
                entry.delete(0, tk.END)
            elif isinstance(entry, tk.Text):
                entry.delete("1.0", tk.END)
    frame.tkraise()


def process_rules(rules_input):
    """
    Spracuje vstupné pravidlá a vráti ich ako slovník: neterminál -> zoznam produkcií (reťazcov).

    Každý riadok s pravidlom by mal byť vo formáte:
        S->aAB | b
    Pravidlo zadané ako "()" sa interpretuje ako prázdny reťazec (ε).
    """
    rules = {}
    for rule in rules_input:
        if "->" in rule:
            left, right = rule.split("->")
            left = left.strip()
            # Rozdelíme produkcie oddelené znakom "|" a odstránime prázdne medzery
            right = [r.strip() for r in right.split("|")]
            # "()" považujeme za prázdny reťazec
            rules[left] = ["" if r == "()" else r for r in right]
    return rules


def find_epsilon_producing(grammar, non_terminals):
    """
    Nájde všetky neterminály, ktoré môžu odvodiť prázdny reťazec (ε).

    Neterminál A je epsilonotvorný, ak:
      1) A -> ε (priamo), alebo
      2) A -> X1 X2 ... Xk, kde každý Xi je tiež epsilonotvorný.

    Realizujeme to iteratívne, kým nepribúdajú nové neterminály.
    """
    epsilon_nt = set()
    changed = True

    while changed:
        changed = False
        for nt, productions in grammar.items():
            if nt in epsilon_nt:
                continue

            for prod in productions:
                # 1) Ak je produkcia priamo prázdna, nt je epsilonotvorný
                if prod == "":
                    epsilon_nt.add(nt)
                    changed = True
                    break
                else:
                    # 2) Skúmame, či všetky neterminály v prod (ak nejaké sú) sú už epsilonotvorné
                    #    a či tam nie je "terminál"
                    all_epsilon = True
                    for ch in prod:
                        if ch in grammar:
                            # ch je neterminál
                            if ch not in epsilon_nt:
                                all_epsilon = False
                                break
                        else:
                            # ch vyzerá byť terminál, teda produkcia nemôže byť prázdna
                            all_epsilon = False
                            break

                    if all_epsilon:
                        epsilon_nt.add(nt)
                        changed = True
                        break

    return epsilon_nt


def parse_production(prod):
    """
    Jednoduché rozdelenie reťazca produkcie na jednotlivé symboly.
    Predpokladáme, že každý neterminál je 1 znak (napr. X, Y)
    a terminály sú takisto 1 znak (napr. a, b).
    """
    return list(prod)


def join_production(symbols):
    """Zloží zoznam symbolov späť do reťazca."""
    return "".join(symbols)


def remove_epsilon_productions(grammar, start_symbol, epsilon_nt):
    """
    Odstráni z gramatiky všetky epsilonové pravidlá (A->ε)
    a pridá "vynechané" neterminály do produkcií,
    presne ako v príklade: A -> aBγ sa rozšíri na A -> aBγ | aγ,
    ak je B epsilonotvorné.

    Rozdiel oproti štandardnému postupu:
      - Ak je štartovací symbol S epsilonotvorný,
        aj tak odstránime S->ε, aby sme docielili,
        že výsledná gramatika už ε nepripúšťa (tak, ako v tvojom príklade).
    """
    import itertools

    new_grammar = {}
    # Inicializujeme slovník neterminálov s prázdnymi množinami produkcií (aby sme predišli duplikátom)
    for A in grammar.keys():
        new_grammar[A] = set()

    # Pre každý neterminál A a každú produkciu p
    for A, productions in grammar.items():
        for p in productions:
            symbols = parse_production(p)

            # Indexy symbolov, ktoré sú epsilonotvorné
            nullable_positions = [i for i, sym in enumerate(symbols) if sym in epsilon_nt]

            # Vygenerujeme všetky podmnožiny nullable_positions
            # (napr. B v "aBγ" -> vynecháme B alebo ho ponecháme)
            subsets = itertools.chain.from_iterable(
                itertools.combinations(nullable_positions, r)
                for r in range(len(nullable_positions) + 1)
            )

            for subset in subsets:
                new_symbols = list(symbols)
                # Odstránime vybrané epsilonotvorné symboly (zprava doľava)
                for idx in sorted(subset, reverse=True):
                    new_symbols.pop(idx)

                new_p = join_production(new_symbols)
                new_grammar[A].add(new_p)

    # Teraz odstránime priame pravidlá A->ε,
    # a to aj v prípade, že A je štartovací symbol
    # (napodobňujeme tvoj príklad, kde S->ε nakoniec nechceme zachovať).
    for A in list(new_grammar.keys()):
        if "" in new_grammar[A]:
            new_grammar[A].remove("")

    # Pridáme nový štartovací neterminál S' ak je pôvodný štartovací neterminál epsilonotvorný
    if start_symbol in epsilon_nt:
        new_start_symbol = f"S'"
        new_grammar[new_start_symbol] = {start_symbol, ""}

    # Premeníme sety späť na listy
    final_grammar = {}
    for A, prod_set in new_grammar.items():
        if prod_set:
            final_grammar[A] = list(prod_set)

    return final_grammar



def find_neperspektivne(grammar, non_terminals):
    """
    Zistí neperspektívne (neproduktívne) neterminály v gramatike.
    """
    productive = set()
    changed = True
    while changed:
        changed = False
        for nt, productions in grammar.items():
            if nt in productive:
                continue
            for prod in productions:
                # Skontrolujeme, či produkcia obsahuje neterminál, ktorý nie je v productive
                contains_nonproductive = False
                for symbol in non_terminals:
                    if symbol in prod and symbol not in productive:
                        contains_nonproductive = True
                        break
                if not contains_nonproductive:
                    productive.add(nt)
                    changed = True
                    break
    return set(non_terminals) - productive


def remove_unproductive(grammar, unproductive):
    """
    Odstráni z gramatiky neperspektívne neterminály a pravidlá, ktoré ich obsahujú.
    """
    clean_grammar = {}
    for nt, productions in grammar.items():
        if nt in unproductive:
            continue
        valid_productions = []
        for prod in productions:
            if any(u_nt in prod for u_nt in unproductive):
                continue
            valid_productions.append(prod)
        if valid_productions:
            clean_grammar[nt] = valid_productions
    return clean_grammar


def find_unreachable(grammar, start_symbol):
    """
    Zistí neterminály, ktoré nie sú dostupné (nedostupné) zo štartovacieho symbolu.
    """
    # Ak nový štartovací symbol S' existuje, nastavíme ho ako start_symbol
    if start_symbol not in grammar:
        return set(grammar.keys())

    reachable = set([start_symbol])
    queue = [start_symbol]

    while queue:
        current_nt = queue.pop()
        for prod in grammar[current_nt]:
            for nt_candidate in grammar.keys():
                if nt_candidate in prod and nt_candidate not in reachable:
                    reachable.add(nt_candidate)
                    queue.append(nt_candidate)

    # V prípade, že nový štartovací symbol S' bol pridaný, zabezpečíme, že sa nezahrnie ako nedostupný.
    if "S'" in grammar:
        reachable.add("S'")

    return set(grammar.keys()) - reachable



def remove_unreachable(grammar, unreachable):
    """
    Odstráni z gramatiky nedostupné neterminály a pravidlá, ktoré ich obsahujú.
    """
    clean_grammar = {}
    for nt, productions in grammar.items():
        if nt in unreachable:
            continue
        valid_productions = []
        for prod in productions:
            if any(u_nt in prod for u_nt in unreachable):
                continue
            valid_productions.append(prod)
        if valid_productions:
            clean_grammar[nt] = valid_productions
    return clean_grammar


def generate_grammar(entry_nt, entry_t, entry_start, entry_rules, label_output):
    """
    Spracuje zadanie gramatiky a zobrazí:
      - Ktoré neterminály sú epsilonotvorné.
      - Gramatiku po odstránení ε-pravidiel (vrátane odstránenia S->ε, ak S bol epsilonotvorný).
      - Neperspektívne neterminály.
      - Nedostupné neterminály.
      - Výslednú gramatiku po odstránení neperspektívnych a nedostupných neterminálov.
    """
    # Načítame vstupy
    non_terminals = [nt.strip() for nt in entry_nt.get().split(",") if nt.strip()]
    terminals = [t.strip() for t in entry_t.get().split(",") if t.strip()]
    start_symbol = entry_start.get().strip()
    rules_input = entry_rules.get("1.0", tk.END).strip().split("\n")

    # 1) Spracujeme pôvodné pravidlá do slovníka
    original_grammar = process_rules(rules_input)

    # 2) Zistíme epsilonotvorné neterminály
    epsilon_nt = find_epsilon_producing(original_grammar, non_terminals)

    # 3) Ak je štartovací neterminál epsilonotvorný, pridáme nový štartovací symbol S'
    if start_symbol in epsilon_nt:
        new_start_symbol = f"S'"
        non_terminals.append(new_start_symbol)  # Pridáme nový štartovací neterminál do zoznamu neterminálov
        original_grammar[new_start_symbol] = {start_symbol, ""}  # Pridáme pravidlo S' -> ε | S

    # 4) Odstránime epsilonové pravidlá (vrátane S->ε, ak S je epsilonotvorný)
    grammar_no_epsilon = remove_epsilon_productions(original_grammar, start_symbol, epsilon_nt)

    # 5) Zistíme a odstránime neperspektívne neterminály
    unproductive = find_neperspektivne(grammar_no_epsilon, non_terminals)
    grammar_after_unproductive = remove_unproductive(grammar_no_epsilon, unproductive)

    # 6) Zistíme a odstránime nedostupné neterminály
    unreachable = find_unreachable(grammar_after_unproductive, start_symbol)
    final_grammar = remove_unreachable(grammar_after_unproductive, unreachable)

    # Vytvoríme reťazec pre gramatiku bez ε-pravidiel
    grammar_no_epsilon_str = []
    for lhs, productions in grammar_no_epsilon.items():
        prod_str = " | ".join("ε" if p == "" else p for p in productions)
        grammar_no_epsilon_str.append(f"{lhs} -> {prod_str}")
    grammar_no_epsilon_str = "\n".join(grammar_no_epsilon_str)

    # Vytvoríme reťazec pre finálnu gramatiku
    final_grammar_lines = []
    for lhs, productions in final_grammar.items():
        prod_str = " | ".join("ε" if p == "" else p for p in productions)
        final_grammar_lines.append(f"{lhs} -> {prod_str}")
    final_grammar_str = "\n".join(final_grammar_lines)

    # Zostavíme správu
    message_parts = []

    # Epsilonotvorné neterminály
    if epsilon_nt:
        eps_str = ", ".join(sorted(epsilon_nt))
        message_parts.append(f"Epsilonotvorné neterminály: {eps_str}")
    else:
        message_parts.append("V tejto gramatike nie sú žiadne epsilonotvorné neterminály.")

    # Gramatika po odstránení ε-pravidiel
    message_parts.append("Gramatika po odstránení ε-pravidiel (vrátane S->ε):\n" + grammar_no_epsilon_str)

    # Neperspektívne neterminály
    if unproductive:
        unprod_str = ", ".join(sorted(unproductive))
        message_parts.append(f"Neperspektívne neterminály: {unprod_str}")

    # Nedostupné neterminály
    if unreachable:
        unreach_str = ", ".join(sorted(unreachable))
        message_parts.append(f"Nedostupné neterminály: {unreach_str}")

    # Výsledná gramatika
    if final_grammar:
        message_parts.append(
            "Výsledná gramatika (po odstránení neperspektívnych a nedostupných neterminálov):\n"
            + final_grammar_str
        )
    else:
        message_parts.append("Po všetkých úpravách nezostala žiadna gramatika.")

    # Skombinujeme a zobrazíme výsledok
    output_msg = "\n\n".join(message_parts)
    label_output.config(text=output_msg)



### FUNKCIE PRE GRAFICKÉ ROZHRANIE ###

def setup_main_frame():
    """Vytvorí a nastaví hlavnú obrazovku aplikácie."""
    frame_main.grid_rowconfigure(0, weight=0)
    frame_main.grid_rowconfigure(1, weight=0)
    frame_main.grid_rowconfigure(2, weight=1)
    frame_main.grid_columnconfigure(0, weight=1)

    title_frame = tk.Frame(frame_main, bg=BG_COLOR)
    title_frame.grid(row=0, column=0, pady=(20, 10), sticky="n")

    tk.Label(title_frame, text="Testovanie ekvivalencie", font=TITLE_FONT, bg=BG_COLOR, fg=TEXT_COLOR).pack()
    tk.Label(title_frame, text="bezkontextových gramatík", font=TITLE_FONT, bg=BG_COLOR, fg=TEXT_COLOR).pack()

    frame_buttons = tk.Frame(frame_main, bg=BG_COLOR)
    frame_buttons.grid(row=1, column=0, pady=(10, 0), sticky="n")

    tk.Button(frame_buttons, text="Zadávanie gramatiky G1",
              command=lambda: show_frame(frame_grammar1),
              font=BUTTON_FONT, width=20, height=2, bg=BUTTON_BG, fg=BUTTON_FG).pack(pady=5)

    tk.Button(frame_buttons, text="Zadávanie gramatiky G2",
              command=lambda: show_frame(frame_grammar2),
              font=BUTTON_FONT, width=20, height=2, bg=BUTTON_BG, fg=BUTTON_FG).pack(pady=5)


def setup_grammar_frame(frame, title_text):
    """Vytvorí a nastaví obrazovku na zadávanie gramatiky."""
    frame.grid_rowconfigure(0, weight=0)
    frame.grid_rowconfigure(1, weight=0)
    frame.grid_rowconfigure(2, weight=0)
    frame.grid_rowconfigure(3, weight=0)
    frame.grid_rowconfigure(4, weight=1)
    frame.grid_columnconfigure(0, weight=1)

    tk.Label(frame, text=title_text, font=TITLE_FONT, bg=BG_COLOR, fg=TEXT_COLOR).grid(row=0, column=0, pady=(10, 5),
                                                                                       sticky="n")

    frame_inputs = tk.Frame(frame, bg=BG_COLOR)
    frame_inputs.grid(row=1, column=0, pady=(5, 10), sticky="n")

    labels_texts = ["N -", "T -", "S -", "P -"]
    entries = []

    for i, text in enumerate(labels_texts):
        tk.Label(frame_inputs, text=text, font=LABEL_FONT, bg=BG_COLOR, fg=TEXT_COLOR).grid(row=i, column=0, pady=5,
                                                                                            sticky="w")
        if i < 3:
            entry = tk.Entry(frame_inputs, font=ENTRY_FONT)
        else:
            entry = tk.Text(frame_inputs, width=40, height=4, font=ENTRY_FONT)
        entry.grid(row=i, column=1, pady=5, padx=10, sticky="ew")
        entries.append(entry)

    frame_inputs.grid_columnconfigure(1, weight=1)

    label_output = tk.Label(frame, text="", font=ENTRY_FONT, bg=BG_COLOR, fg=TEXT_COLOR_ALT)
    label_output.grid(row=2, column=0, pady=10)

    frame_buttons = tk.Frame(frame, bg=BG_COLOR)
    frame_buttons.grid(row=3, column=0, pady=(10, 0), sticky="n")

    tk.Button(frame_buttons, text="Zobraziť gramatiku",
              command=lambda: generate_grammar(*entries, label_output),
              font=BUTTON_FONT, bg=BUTTON_BG, fg=BUTTON_FG).pack(pady=5)

    tk.Button(frame_buttons, text="Späť",
              command=lambda: show_frame(frame_main, entries),
              font=BUTTON_FONT, bg=BUTTON_BG, fg=BUTTON_FG).pack(pady=5)


### HLAVNÉ NASTAVENIA GUI ###

BG_COLOR = '#d0e7f9'
TEXT_COLOR = '#00274d'
TEXT_COLOR_ALT = '#00509e'
BUTTON_BG = '#00509e'
BUTTON_FG = 'white'

TITLE_FONT = ("Arial", 20, "bold")
LABEL_FONT = ("Arial", 14)
ENTRY_FONT = ("Arial", 14)
BUTTON_FONT = ("Arial", 16)

root = tk.Tk()
root.title("Testovanie")
root.geometry("800x500")
root.configure(bg=BG_COLOR)

container = tk.Frame(root)
container.pack(fill="both", expand=True)

container.grid_rowconfigure(0, weight=1)
container.grid_columnconfigure(0, weight=1)

frame_main = tk.Frame(container, bg=BG_COLOR)
frame_grammar1 = tk.Frame(container, bg=BG_COLOR)
frame_grammar2 = tk.Frame(container, bg=BG_COLOR)

for frame in (frame_main, frame_grammar1, frame_grammar2):
    frame.grid(row=0, column=0, sticky='nsew')

setup_main_frame()
setup_grammar_frame(frame_grammar1, "Zadávanie gramatiky G1")
setup_grammar_frame(frame_grammar2, "Zadávanie gramatiky G2")

show_frame(frame_main)

root.mainloop()
