const questionnaires = {
  kiszallitas: {
    q0: {
      text: "Sikerült a kiszállítás?",
      next: {
        Igen: "q1",
        Nem: "q2"
      }
    },
    q1: {
      text: "Minden rendben volt?",
      next: {
        Igen: "q11",
        Nem: "q12"
      }
    },
    q2: {
      text: "Mi miatt nem sikerült a kiszállítás?",
      next: {
        "Hibás cím": "q21",
        "Nem vette át": "q22",
        "Sérült csomag": "q23"
      }
    },
    q11: {
      text: "Akkor sikeresen lezártuk a rendelést!",
      next: {

      }
    },
    q12: {
      text: "Mi volt a gond?",
      next: {
        "Késés": "q121",
        "Elégedetlen ügyfél": "q122"
      }
    },
    q121: {
      text: "Késéssel, de ki lett szállítva",
      next: {

      }
    },
    q122: {
      text: "Megtartotta a csomagot?",
      next: {
        Nem: "q1222"
      }
    },
    q1222: {
      text: "Mikor fogja visszaküldeni?",
      next: {

      }
    },
    q21: {
      text: "Adjon meg az ügyfél egy új címet!",
      next: {

      }
    },
    q22: {
      text: "Mikor tudná átvenni?",
      next: {
        Ma: "q221",
        Holnap: "q222",
        "Máskor": "q223"
      }
    },
    q23: {
      text: "Visszaküldi vagy megtartja?",
      next: {
        "Visszaküldi": "q1222"
      }
    },
    q221: {
      text: "Küldje vissza akkor ma!",
      next: {

      }
    },
    q222: {
      text: "Küldje vissza akkor holnap!",
      next: {

      }
    },
    q223: {
      text: "Vedd fel, hogy mikor tudná visszaküldeni!",
      next: {

      }
    }
  },
  munka: {
    munkaq0: {
      text: "Dolgoztal ma?",
      next: {
        Igen: "munkaq1",
        Nem: "munkaq2"
      }
    },
    munkaq1: {
      text: "Jo volt?",
      next: {

      }
    },
    munkaq2: {
      text: "Munkanelkuli vagy?",
      next: {

      }
    }
  },
  bebi: {
    bebiq0: {
      text: "Tudsz ma vigyazni a gyerekre?",
      next: {
        Igen: "bebiq1",
        Nem: "bebiq2"
      }
    },
    bebiq1: {
      text: "Orulok neki. gyere delutan 5re",
      next: {

      }
    },
    bebiq2: {
      text: "sajnalom, miert nem?",
      next: {

      }
    }
  },
  beszallitas: {
    besz1q0: {
      text: "Sikerült a beszállítás?",
      next: {
        Igen: "besz1q1",
        Nem: "besz1q2"
      }
    },
    besz1q1: {
      text: "Örülök hogy sikerült",
      next: {

      }
    },
    besz1q2: {
      text: "Kár, hogy nem sikerült",
      next: {

      }
    }
  },
  meleg: {
    melegq0: {
      text: "Meleg van?",
      next: {
        Igen: "melegq1",
        Nem: "melegq2"
      }
    },
    melegq1: {
      text: "Hány fok volt tegnap?",
      next: {
        "30": "melegq11",
        "35": "melegq12"
      }
    },
    melegq2: {
      text: "Akkor nincs meleg",
      next: {

      }
    },
    melegq11: {
      text: "Akkor 30 fok",
      next: {
        "Nem iagz, mert 28": "melegq111",
        "Igazad van": "melegq112"
      }
    },
    melegq12: {
      text: "Akkor 35 fok",
      next: {

      }
    },
    melegq111: {
      text: "Akkor 28 foksz",
      next: {

      }
    },
    melegq112: {
      text: "Akkor igazad van!",
      next: {

      }
    }
  },
  sdgsfdhreh: {
    q0: {
      text: "sdgfsgfsd",
      next: {
        sdgsdg: "q1",
        gdsgd: "q2"
      }
    },
    q1: {
      text: "gfsdígsdfg",
      next: {

      }
    },
    q2: {
      text: "fsdígsfgsíf",
      next: {
        gsdg: "q21",
        qgfdss: "q22"
      }
    },
    q21: {
      text: "sgdfgdsaf",
      next: {

      }
    },
    q22: {
      text: "gsdsadf",
      next: {

      }
    }
  },
  edzes: {
    edzesq0: {
      text: "Edzettél ma?",
      next: {
        Igen: "edzesq1",
        Nem: "edzesq2"
      }
    },
    edzesq1: {
      text: "Mire edzettél?",
      next: {
        Mell: "edzesq11",
        "Hát": "edzesq12",
        "Láb": "edzesq13",
        Kar: "edzesq14"
      }
    },
    edzesq2: {
      text: "Szégyeld magad!",
      next: {

      }
    },
    edzesq11: {
      text: "jó kis mell edzés",
      next: {

      }
    },
    edzesq12: {
      text: "jó kis hát edzés",
      next: {

      }
    },
    edzesq13: {
      text: "Jó kis láb edzés",
      next: {

      }
    },
    edzesq14: {
      text: "Jó kis kar edzés",
      next: {

      }
    }
  },
  edzes1: {
    edzes1q0: {
      text: "Edzettél ma?",
      next: {
        Igen: "edzesq1",
        Nem: "edzesq2"
      }
    },
    edzes1q1: {
      text: "Mire edzettél?",
      next: {
        Mell: "edzes1q11",
        "Hát": "edzes1q12",
        "Láb": "edzes1q13",
        Kar: "edzes1q14"
      }
    },
    edzes1q2: {
      text: "Szégyeld magad!",
      next: {

      }
    },
    edzes1q11: {
      text: "jó kis mell edzés",
      next: {

      }
    },
    edzes1q12: {
      text: "jó kis hát edzés",
      next: {

      }
    },
    edzes1q13: {
      text: "Jó kis láb edzés",
      next: {

      }
    },
    edzes1q14: {
      text: "Jó kis kar edzés",
      next: {

      }
    }
  },
  zene: {
    zeneq0: {
      text: "Hallgattál ma zenét?",
      next: {
        Igen: "zeneq1",
        Nem: "zeneq2"
      }
    },
    zeneq1: {
      text: "Milyen zenét hallgattál?",
      next: {
        Mario: "zeneq11",
        Massimo: "zeneq12",
        "Egyéb": "zeneq13"
      }
    },
    zeneq2: {
      text: "Kár higy nem hallgattál zenét",
      next: {

      }
    },
    zeneq11: {
      text: "Jó kis Kunu Mário",
      next: {

      }
    },
    zeneq12: {
      text: "Olaszos Masszimó",
      next: {

      }
    },
    zeneq13: {
      text: "Milyen zenét hallgattál akkor?",
      next: {

      }
    }
  },
  teszteles: {
    tesztelesq0: {
      text: "Ez egy teszt sablon. Rendben?",
      next: {
        Igen: "tesztelesq1",
        Nem: "tesztelesq2"
      }
    },
    tesztelesq1: {
      text: "Most kiderül hogy jol mukodik e.",
      next: {

      }
    },
    tesztelesq2: {
      text: "Mi a gond ezzel?",
      next: {

      }
    }
  },
  teszt2: {
    teszt2q0: {
      text: "Masodik tesztem, hogy ujra kell-e inditani a szervert.",
      next: {
        "Szerintem jo lesz.": "teszt2q1",
        "Szerintem nem.": "teszt2q2"
      }
    },
    teszt2q1: {
      text: "Jó lett :)",
      next: {

      }
    },
    teszt2q2: {
      text: "Jó lett ....",
      next: {

      }
    }
  },
  sportolas: {
    sportq0: {
      text: "Sportolsz valamit?",
      next: {
        Igen: "sportq1",
        Nem: "sportq2"
      }
    },
    sportq1: {
      text: "Mit sportolsz?",
      next: {
        Foci: "sportq11",
        Kondi: "sportq12",
        Hoki: "sportq13",
        "Egyéb": "sportq14"
      }
    },
    sportq2: {
      text: "Szégyeld magad!",
      next: {

      }
    },
    sportq11: {
      text: "Mióta focizol?",
      next: {
        "Régóta": "sportq111",
        "Nem régóta": "sportq112"
      }
    },
    sportq12: {
      text: "Mióta kondizol?",
      next: {
        "Régóta": "sportq121",
        "Nem régóta": "sportq122"
      }
    },
    sportq13: {
      text: "Jéghoki",
      next: {

      }
    },
    sportq14: {
      text: "Mit sportolsz?",
      next: {

      }
    },
    sportq111: {
      text: "Akkor régóta focizol!",
      next: {

      }
    },
    sportq112: {
      text: "Akkor nem régóta focizol!",
      next: {

      }
    },
    sportq121: {
      text: "Akkor már szteroidozol is",
      next: {

      }
    },
    sportq122: {
      text: "Akkor nem régóta kondizol",
      next: {

      }
    }
  },
  uzenetindito: {
    hozzajarulas: {
      text: "Hozzájárulsz ahhoz, hogy innentől üzenetet küldhessek neked, és ezeket az üzeneteket adatbázisban tároljam lokálisan?",
      next: {

      }
    }
  },
  "3gomb_teszt": {
    "3gombq0": {
      text: "Sok opció megfog jelenni?",
      next: {

      }
    }
  },
  kerdoiv_szerkeszto_teszt: {
    szerkeszto_tesztq0: {
      text: "ez egy teszt",
      next: {

      }
    }
  },
  kerdoiv_szerkeszto_teszt_utility: {
    szerkeszto_tesztq_util0: {
      text: "ez egy teszt",
      next: {

      }
    }
  }
};

module.exports = questionnaires;
